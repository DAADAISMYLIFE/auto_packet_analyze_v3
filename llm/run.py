import sys, json, re, os, time, hashlib

from tools import Tools, compact_evidence, is_threat_alert, is_malware_comm_alert
from config import (MODEL, OPTS, THINK, NUM_CTX, VERDICT_SCHEMA, REPORT_SCHEMA,
                    SYSTEM_PROMPT_TRIAGE, SYSTEM_PROMPT_FORENSIC)
# ollama 는 LLM 호출 함수 안에서 지연 import — 가드(코드 소유 후처리)는 ollama 없이도
# 로드/테스트 가능해야 한다 (test_guards.py 가 로컬 CPU 에서 돈다).

# IOC 값에서 진짜 IP/도메인 토큰만 뽑는 정규식 (LLM 장식·JSON 누출 제거용)
_IPV4 = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
_DOMAIN = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?")

# dom_ok 역-suffix('관측 서브도메인의 부모 인정')가 TLD 까지 올라가는 것 차단
# ('com' 차단 룰 방지 — 단일라벨은 무조건 기각, 흔한 공용접미사도 기각)
PUBLIC_SUFFIX_FLOOR = {"co.kr", "or.kr", "go.kr", "ne.kr", "pe.kr",
                       "co.uk", "com.br", "com.au", "co.jp", "com.cn"}

# 정상 서비스가 거의 안 쓰는 최상위도메인 — 악성 후속/DGA 상투. attach_iocs_from_dns 의 승격 게이트.
# (.ru/.com 등 정상 트래픽 많은 TLD 는 제외 — 오탐 위험. detection 용, 차단은 make_policy 소유.)
SUSP_TLD = re.compile(r"\.(su|cc|cyou|xyz|top|tk|gq|ml|cf|ga)$")

# 위협 alert 판정은 tools.is_threat_alert 가 단일 구현 (evidence.threat_class 우선, 구 evidence 정규식 폴백).
_is_threat_alert = is_threat_alert

# LLM 이 attacks[].technique 에 적는 C2/유출 계열 라벨 — 이런 attack 의 target/target_host 는
# '피격자'가 아니라 '악성 인프라'다(내부→외부 통신 기록). 시그니처가 침묵하는 C2 는 c2_flagged
# (알럿 기반)가 못 받쳐주므로 이게 두 번째 보호막이다 (q2 실측: 136.243.24.249·46.108.156.146 이
# alert 0건이라 표적으로 오인 삭제됨 / 2021-06-16 hadevatjulps.com 도메인 동일).
_C2_TECHNIQUE = re.compile(r"c2|cnc|command.?and.?control|beacon|checkin|exfil|tunnel", re.I)


def _is_c2_attack(a):
    return bool(_C2_TECHNIQUE.search(str(a.get("technique") or "")))


# 컨텍스트 예산 — NUM_CTX 의 일부만 입력에 쓴다(사고 토큰 + 출력 여유). triage 는 3지선다라 더 짧게.
#   예산 안에 들어가면 뷰 level 0 (= 오늘과 동일). 넘칠 때만 '신호 없는 행'부터 단계적으로 줄인다.
BUDGET_FRACTION = {"forensic": 0.6, "triage": 0.25}


class LLMError(RuntimeError):
    """ollama 호출 자체가 실패 (컨텍스트 초과·서버 다운 등). 파싱 실패와 구분."""


def estimate_tokens(text):
    """qwen/llama 계열 토크나이저 근사: 숫자는 자릿수마다 1토큰, 구두점 1토큰, 나머지 ≈3.5자/토큰.
    (3.3자/토큰 단순 추정은 IP·epoch·해시 덩어리인 evidence 에서 40% 과소 — q2 실증.)"""
    d = sum(c.isdigit() for c in text)
    p = sum(c in '.,:"[]{}/-_=?&%' for c in text)
    return int(d + p + (len(text) - d - p) / 3.5)


def _bundle(tools, http):
    return json.dumps(compact_evidence({
        "deviations": tools.evidence.get("deviations"),   # ← 정상 대비 편차(코드가 랭크). 여기부터 본다.
        "meta": tools.get_meta(),
        "hosts": tools.get_hosts_info(),
        "alerts": tools.get_alerts(),                       # threat_class 포함 — 코드가 아는 위협/정황 구분
        "external": tools.get_external(),
        "http": http,                                       # 단계적 뷰 (tools.http_view)
        "files": tools.get_files(),
        "lateral_movement": tools.get_lateral_movement(),
        "anomalies": tools.get_anomalies(),
        "signals": tools.get_signals(),
    }), ensure_ascii=False, default=str)


def _tier1(tools, mode="forensic"):
    """LLM 에 주입하는 tier1 근거 번들. 예산에 맞을 때까지 http 뷰를 강등하고, 그래도 넘치면
    호출 '전'에 실패한다 — ollama 는 안 들어가는 user 메시지를 잘라주지 않고 통째로 버린 뒤
    500 을 내며, 그 전에 12분을 태운다(q2 실증)."""
    budget = int(NUM_CTX * BUDGET_FRACTION.get(mode, 0.6))
    text = est = level = None
    for level in range(Tools.HTTP_VIEW_LEVELS):
        text = _bundle(tools, tools.http_view(level))
        est = estimate_tokens(text)
        if est <= budget:
            break
    print(f"[tier1:{mode}] http-view level={level}  {len(text):,} chars ≈ {est:,} tokens  "
          f"(budget {budget:,} / NUM_CTX {NUM_CTX:,})")
    if est > budget:
        raise LLMError(f"tier1 ≈{est:,} tokens > budget {budget:,} (최대 강등 후에도) — 호출 안 함. "
                       f"NUM_CTX 상향 또는 evidence 캡 축소 필요")
    return text


def _chat(stage, **kw):
    """ollama chat 래퍼 — (1) 서버 에러를 LLMError 로 (main 이 보고서에 기록), (2) prefill/decode
    실측을 찍는다. '15분이 어디로 가는가'를 감이 아니라 숫자로 — 사고 토큰은 decode 에 포함되므로
    decode 가 크면 사고가 범인, prefill 이 크면 evidence 크기가 범인이다."""
    from ollama import chat
    t0 = time.time()
    try:
        res = chat(**kw)
    except Exception as ex:                           # ResponseError(500 등)·연결 실패 모두
        raise LLMError(f"{type(ex).__name__}: {ex}") from ex
    pe = getattr(res, "prompt_eval_count", 0) or 0
    ped = ((getattr(res, "prompt_eval_duration", 0) or 0) / 1e9) or 1e-9
    ec = getattr(res, "eval_count", 0) or 0
    ed = ((getattr(res, "eval_duration", 0) or 0) / 1e9) or 1e-9
    think_chars = len(getattr(res.message, "thinking", None) or "")
    print(f"[llm:{stage}] {time.time() - t0:.0f}s — prefill {pe:,}tok/{ped:.0f}s({pe / ped:.0f}tok/s)"
          f" decode {ec:,}tok/{ed:.0f}s({ec / ed:.1f}tok/s) thinking {think_chars:,}자")
    return res


def triage(tools):
    res = _chat("triage", model=MODEL, format=VERDICT_SCHEMA,   # ← format 이 강제 선택
               think=THINK,                            # .env THINK — qwen3.8 은 추론이 본체(끄면 판단력 급감)
               messages=[{"role": "system", "content": SYSTEM_PROMPT_TRIAGE},
                         {"role": "user", "content": "Triage this capture.\n\n# Tier-1 Evidence\n" + _tier1(tools, "triage")}],
               options=OPTS)

    content = res.message.content
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # grounds 폭주로 JSON 이 잘려도 verdict 는 맨 앞이라 살아있음 → 정규식으로 복구
        m = re.search(r'"verdict"\s*:\s*"(no_incident|suspicious|confirmed)"', content or "")
        if m:
            print(f"[triage] JSON 잘림 — verdict 복구: {m.group(1)}")
            return {"verdict": m.group(1),
                    "grounds": ["(grounds 폭주로 잘림 — verdict 만 복구)"]}
        print("[triage] verdict 복구 실패 — suspicious 폴백")
        print("  content(repr):", repr((content or "")[:200]))   # 비었나/뭐가왔나 진단용
        print("  thinking 있었나:", bool(getattr(res.message, "thinking", None)))
        return {"verdict": "suspicious",
                "grounds": ["triage 출력 파싱 실패 — 안전을 위해 분석 단계로 에스컬레이트"]}


def _forensic_messages(tools):
    """forensic chat 메시지 — 프롬프트 해시(캐시 키)의 유일한 입력.
    분석 절차·판정 rubric 은 전부 forensic.md(system)에 있다 — 프롬프트는 .md 단일 소스."""
    user = ("Analyze this incident and return the structured JSON.\n\n"
            "# Tier-1 Evidence\n" + _tier1(tools, "forensic"))
    return [{"role": "system", "content": SYSTEM_PROMPT_FORENSIC},
            {"role": "user", "content": user}]


def _cache_path(tools):
    return os.path.join(tools.base, "forensic_raw.json")


def _prompt_sha(messages):
    # 프롬프트(=system+tier1) + 모델 + think 이 같으면 forensic 출력을 재생해도 된다.
    #   evidence·뷰·프롬프트가 바뀌면 sha 가 바뀌어 자동으로 캐시 미스(정확).
    blob = json.dumps(messages, ensure_ascii=False, sort_keys=True) + f"|{MODEL}|think={THINK}"
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _parse_forensic(content):
    try:
        return json.loads(content)
    except (json.JSONDecodeError, TypeError):
        print("[forensic] 구조화 JSON 파싱 실패 — content(repr):", repr((content or "")[:300]))
        return None


def forensic(tools, mode="auto"):
    """forensic 분석. mode:
       auto   — evidence 프롬프트 해시가 캐시와 같으면 LLM 생략하고 재생(코드만 고친 반복=2초),
                다르면 LLM 호출 후 캐시 저장. (기본)
       fresh  — 항상 LLM 호출 + 캐시 덮어씀.
       replay — LLM 절대 호출 안 함(ollama/ GPU 없이 로컬에서 가드·정책·score 반복). 캐시 없으면 에러.
                프롬프트 해시가 달라도 재생하되 'stale' 경고 (가드 로직만 테스트할 때).
    LLM 사고(케이스당 10~20분)를 매 코드 수정마다 다시 태우지 않게 하는 개발 루프 가속기."""
    cache = _cache_path(tools)
    cached = json.load(open(cache, encoding="utf-8")) if os.path.exists(cache) else None

    if mode == "replay":
        if not cached:
            raise LLMError(f"replay 인데 캐시 없음: {cache} (먼저 fresh/auto 로 1회 생성)")
        sha = None
        try:
            sha = _prompt_sha(_forensic_messages(tools))
        except LLMError:
            pass
        stale = " ‼stale(evidence/프롬프트 변경됨 — 가드 로직만 검증용)" if sha and sha != cached.get("prompt_sha") else ""
        print(f"[forensic] 캐시 재생 — LLM 생략{stale}  ({cache})")
        return _parse_forensic(cached.get("content"))

    messages = _forensic_messages(tools)          # _tier1 예산 초과면 여기서 LLMError (호출 전)
    sha = _prompt_sha(messages)
    if mode == "auto" and cached and cached.get("prompt_sha") == sha:
        print(f"[forensic] 캐시 히트(evidence 동일) — LLM 생략, 재생  ({cache})")
        return _parse_forensic(cached.get("content"))

    res = _chat("forensic", model=MODEL, format=REPORT_SCHEMA, think=THINK,
                messages=messages, options=OPTS)
    content = res.message.content
    try:
        with open(cache, "w", encoding="utf-8") as f:
            json.dump({"prompt_sha": sha, "model": MODEL, "think": THINK,
                       "content": content}, f, ensure_ascii=False, indent=2)
    except OSError as ex:
        print(f"[forensic] 캐시 저장 실패(무시): {ex}")
    return _parse_forensic(content)


# =============================================================================
# 코드 소유 후처리(가드) — "코드가 팩트, LLM 이 판단"
# =============================================================================

class CaseContext:
    """케이스 하나의 '집합 장부' — 가드들이 각자 복붙 계산하던 내부IP/AD존/외부관측IP/공격표적을
    forensic 직후 한 번만 계산해 공유한다. 판정 기준(예: 내부 자산의 정의)을 바꿀 때 여기
    한 곳만 고치면 모든 가드에 동시에 반영된다.
    """
    def __init__(self, analysis, tools):
        self.tools = tools
        ev = tools.evidence
        hosts = ev.get("hosts", [])
        self.hosts_by_ip = {h.get("ip"): h for h in hosts}
        self.internal_ips = {str(h.get("ip")).lower() for h in hosts if h.get("ip")}
        # AD 존 식별 (결정론적, 이중 신호): kerberos realm + '_msdcs.<존>' SRV 질의
        # (kerberos 트래픽이 없는 캡처에서도 _msdcs 로 존이 잡힘)
        self.ad_domains = {str(h.get("ad_domain")).lower() for h in hosts if h.get("ad_domain")}
        for d in ev.get("external", {}).get("domains", []) or []:
            q = str(d.get("query") or "").lower()
            if "._msdcs." in q:
                self.ad_domains.add(q.split("._msdcs.", 1)[1])
        # 외부 관측 IP (아웃바운드 dst 집계) — 인바운드 공격자는 여기 없고 alert src 로만 등장
        self.external_ips = {str(x.get("ip")).lower()
                             for x in ev.get("external", {}).get("ips", []) if x.get("ip")}
        # 멀웨어-통신 alert(MALWARE/CNC/RAT…)가 가리키는 외부 IP = 악성 인프라 확정.
        #   LLM 이 C2 통신을 attacks[].target 에 적으면 '피격자 제거'가 C2 를 지우고 승격기까지
        #   막아 차단정책이 통째로 비는 실전 결함(2021-06-16·2024-07-30·2025-01-22 실증).
        #   시그니처 카테고리(결정론)로 표적 취급에서 보호한다 — WEB_SERVER/EXPLOIT/SCAN 류의
        #   dst(아웃바운드 공격의 진짜 피격자)는 보호하지 않아 자폭 방지 원칙은 유지된다.
        self.c2_flagged = set()
        for a in ev.get("alerts", []):
            if not is_malware_comm_alert(a):
                continue
            for ip in (a.get("src_ips") or []) + (a.get("dst_ips") or []):
                si = str(ip).lower()
                if si not in self.internal_ips:
                    self.c2_flagged.add(si)
        # 공격 표적(피격자) IP — IOC 가 아니다. 승격기가 이걸 c2 로 되살리면 '피해자를 차단'하는 자폭.
        self.attack_targets = set()
        for t in (analysis.get("attacks") or []):
            m = _IPV4.search(str(t.get("target") or ""))
            if not m:
                continue
            ip = m.group(0).lower()
            if ip in self.c2_flagged or _is_c2_attack(t):   # C2 오기(誤記) 보호: alert 기반 + technique 기반
                continue
            self.attack_targets.add(ip)
        # 그라운딩 기준집합 = evidence 의 '외부 관측' IP/도메인/해시 (내부 자산 원천 제외)
        self.observed = tools.observed_iocs()

    def is_internal_asset(self, host):
        """내부 호스트 IP, 또는 AD 존/하위 이름(desktop-x.saltmobsters.com) = 우리 자산 → IOC 아님."""
        return host in self.internal_ips \
            or any(host == a or host.endswith("." + a) for a in self.ad_domains)


def attach_identity(analysis, ctx):
    """victims[] 의 ip 조인 정체(mac/hostname/username)와 patient_zero 를 코드가 확정.

    mac/hostname/username 은 LLM 이 hosts[] 에서 베끼는 값이라 두 사고가 난다:
      (1) 전사 손상 — 'CFA3467' 류 hostname 오염, mac 오염.
      (2) 통째 생략 — 스키마 optional 이라 format 강제 모델이 곧잘 빼먹음.
    또 LLM 은 ip/patient_zero 에 설명을 덧붙이기도 한다
    ('10.6.15.119 (First observed...)') → clean_ip 로 IP 토큰만 뽑아 정규화.
    ip 만 앵커로 쓰고 정체는 코드가 evidence 로 덮어쓴다(없으면 None, 환각 제거).
    """
    by_ip = ctx.hosts_by_ip
    host_ips = set(by_ip)

    def clean_ip(v):
        # 장식/손상 방어 — 값에서 IP 를 뽑되 evidence 호스트로만 복구(추측 금지):
        #   1) 정상 IPv4 토큰이 호스트면 그것 ('10.6.15.119 (First observed...)' → 10.6.15.119)
        #   2) 없으면 숫자군 4개를 재조립해 호스트면 채택 ('10.6_15.187' → 10.6.15.187, 구분자 손상)
        # 호스트 대조로만 복구 → 환각·자릿수 손상은 원문 유지(정상 호스트 오인 방지).
        s = str(v or "")
        ips = _IPV4.findall(s)
        for i in ips:
            if i in host_ips:
                return i
        groups = re.findall(r"\d{1,3}", s)
        if len(groups) == 4 and ".".join(groups) in host_ips:
            return ".".join(groups)
        return ips[0] if ips else v

    for v in analysis.get("victims", []):
        v["ip"] = clean_ip(v.get("ip"))
        h = by_ip.get(v["ip"]) or {}
        v["mac"] = h.get("mac")
        v["hostname"] = h.get("hostname")
        v["username"] = h.get("username")
        v["role"] = h.get("role")            # role 도 코드가 evidence 로 확정(LLM 오라벨 방지)
    if analysis.get("patient_zero"):
        analysis["patient_zero"] = clean_ip(analysis["patient_zero"])


def demote_infra_victims(analysis, ctx):
    """인프라(DC/DNS)를 '피해자'로 부르는 자폭 방지 (코드 소유).

    모델은 워크스테이션→DC 의 정상 AD RPC(DRSCrackNames/SAMR/LSA)를 credential_theft/
    recon 으로 오번역하고, 그 표적인 DC 를 status=compromised 로 올린다 → 차단정책이 DC 를
    격리하면 실제 장애(자폭). DC 가 '인증을 받는 것'은 침해가 아니다.
      - 단, 진짜 감염된 DC 는 다른 호스트와 같은 잣대로 그대로 compromised 로 둔다:
        DC 가 위협 alert 의 '출발지'이거나, 외부로 나가는 alert 의 출발지일 때.
        정상 AD RPC 는 Suricata alert 를 만들지 않으므로 이 조건은 인바운드 인증과 안 겹친다.
      - role 은 attach_identity 가 evidence 로 이미 확정했으므로 신뢰한다.
    """
    alerts = ctx.tools.evidence.get("alerts", [])

    def originates_threat(ip):
        ip = str(ip).lower()
        for a in alerts:
            if ip not in {str(s).lower() for s in (a.get("src_ips") or [])}:
                continue
            if _is_threat_alert(a):                          # DC 가 위협 카테고리 alert 의 출발지
                return True
            if {str(d).lower() for d in (a.get("dst_ips") or [])} & ctx.external_ips:
                return True                                  # DC 가 외부로 악성 통신
        return False

    demoted = []
    for v in analysis.get("victims", []):
        if v.get("role") in ("domain_controller", "dns_server") \
                and v.get("status") == "compromised" \
                and not originates_threat(v.get("ip")):
            v["status"] = "infrastructure"
            v["malware"] = []
            demoted.append(v.get("ip"))
    if demoted:
        analysis["_demoted_infra"] = demoted


def attach_hashes(analysis, ctx):
    """iocs.hashes 를 evidence 의 malware-candidate 파일에서 코드가 채운다 (해시 블라인드니스 방지).

    LLM 은 files[] 를 보고도 hashes 를 거의 항상 [] 로 낸다 → 코드가 확정값으로 덮어쓴다.
    ms-pol(정상 GPO) + 업데이트 인프라(windowsupdate 등)가 서빙한 x-dosexec 은 serving-host
    조인으로 제외한다 (MS Defender 업데이트 해시를 차단정책에 넣던 오탐 차단).
    제외분은 침묵하지 않고 _excluded_benign_hashes 로 노출(투명).
    """
    res = ctx.tools.malware_candidate_hashes()
    analysis.setdefault("iocs", {})["hashes"] = res["malware"]
    if res["benign_excluded"]:
        analysis["_excluded_benign_hashes"] = res["benign_excluded"]


def ground_iocs(analysis, ctx):
    """iocs 의 IP/도메인을 evidence 관측집합과 exact-match 대조해 오염/환각을 제거한다.
    (차단정책 안전장치 — 오염된 IP 로 깨진 Snort 룰이 나가는 것을 원천 차단.)

    - 복원은 안 함: '1para.36.191.35' 를 '194.36.191.35' 로 추측하지 않는다(추측이
      틀리면 정상 서버 차단 위험). evidence 에 없으면 그냥 제거.
    - 도메인은 suffix 허용: 'mail.staroxalate.com' 은 'staroxalate.com' 관측으로 인정.
    - IP 버킷(c2/delivery/exfil)에 URL(host/path)이나 도메인이 잘못 담기면 host 만
      떼어 관측 도메인일 때 domains 로 이관(salvage) — 버킷 오배치 구제.
    - 내부 자산(호스트 IP, AD 존/하위 이름)은 관측 여부와 무관하게 기각 — 자기 DC/
      워크스테이션을 차단정책이 막는 자폭 방지. 사유는 '내부 자산'으로 구분(환각과 다름).
    - 단일라벨(TLD)·공용접미사 도메인은 기각 — 'com' 차단 룰 방지 (PUBLIC_SUFFIX_FLOOR).
    - 제거분은 조용히 버리지 않고 _rejected_iocs 로 노출(사람 검토용).
    - hashes 는 이미 attach_hashes 가 evidence 에서 코드로 채우므로 건드리지 않는다.
    """
    obs = ctx.observed

    def host_of(v):
        # LLM 이 IP/도메인에 붙이는 오염을 벗겨 진짜 토큰만 추출:
        #   'http://host/path'(스킴·경로), '1.2.3.4 (HTTP Beacon)'(주석), "dom.com']},"(JSON 누출) 등.
        # obs 대조는 그대로라 환각·손상 오타는 여전히 탈락(안전) — 값을 '추측 복원'하지는 않음.
        s = re.sub(r"^[a-z]+://", "", str(v).strip().lower()).split("/", 1)[0]
        m = _IPV4.search(s)
        if m:
            return m.group(0)
        m = _DOMAIN.search(s)
        return m.group(0) if m else s

    def dom_ok(d):
        d = d.lower()
        if "." not in d or d in PUBLIC_SUFFIX_FLOOR:   # TLD/공용접미사 차단
            return False
        return any(d == o or d.endswith("." + o) or o.endswith("." + d) for o in obs["domains"])

    iocs = analysis.get("iocs", {})
    rejected = []
    salvaged_doms = []          # IP 버킷에 잘못 담긴 도메인 → domains 로 이관
    for bucket in ("c2", "delivery", "exfil"):
        kept = []
        for ip in iocs.get(bucket, []):
            host = host_of(ip)
            if ctx.is_internal_asset(host):      # 내부 자산 IP → 차단정책 자폭 방지
                rejected.append({"kind": "ip", "bucket": bucket, "value": ip,
                                 "reason": "내부 자산 (IOC 아님)"})
            elif host in obs["ips"]:
                kept.append(host)
            elif dom_ok(host):
                salvaged_doms.append(host)
            else:
                rejected.append({"kind": "ip", "bucket": bucket, "value": ip,
                                 "reason": "evidence 미관측 (오염/환각)"})
        iocs[bucket] = kept
    kept_doms, seen = [], set()
    for d in list(iocs.get("domains", [])) + salvaged_doms:
        host = host_of(d)
        if host in seen:
            continue
        if not host:                             # 토큰 추출 실패도 침묵하지 않고 기록
            rejected.append({"kind": "domain", "value": d,
                             "reason": "빈 값 (토큰 추출 실패)"})
            continue
        if ctx.is_internal_asset(host):          # 내부 AD 존/하위 이름 → 자산
            seen.add(host)
            rejected.append({"kind": "domain", "value": d,
                             "reason": "내부 자산 (IOC 아님)"})
        elif dom_ok(host):
            seen.add(host)
            kept_doms.append(host)
        else:
            rejected.append({"kind": "domain", "value": d,
                             "reason": "evidence 미관측 (오염/환각)"})
    iocs["domains"] = kept_doms
    if rejected:
        analysis["_rejected_iocs"] = rejected


def annotate_attacks(analysis, ctx):
    """attacks[] 후처리 (코드 소유):

      1. actor_scope/target_scope 를 host inventory 로 채운다 — 내부/외부는
         evidence.hosts 유무로 결정론적. 차단 반응 분기의 근거가 된다:
           actor internal → 침해된 발판일 수 있음(RCE/pivot) → 호스트 격리 대상
           actor external → 외부 공격자 → 경계에서 IP 차단 대상
      2. target(피격자)은 IOC 가 아니므로 iocs(c2/delivery/exfil/domains)에서 제거.
         스키마에 attacks.target 칸을 줬어도 모델이 습관적으로 c2 에 또 넣을 수 있어
         코드가 최종적으로 빼낸다(ground_iocs 와 같은 '코드가 안전을 소유' 원칙).
         자기/피해 서버를 차단정책이 막는 자폭 방지. 제거분은 _removed_attack_targets 로 노출.
    """
    attacks = analysis.get("attacks") or []
    if not attacks:
        return

    def scope(ip):
        if not ip:
            return "unknown"
        return "internal" if str(ip).lower() in ctx.internal_ips else "external"

    targets, thosts, c2_protected = set(), set(), set()
    for a in attacks:
        a["actor_scope"] = scope(a.get("actor"))       # 코드가 확정 (LLM 값 덮어씀)
        a["target_scope"] = scope(a.get("target"))
        c2ish = _is_c2_attack(a)                       # C2/유출 통신 기록 — target 은 악성 인프라
        if a.get("target"):
            t = str(a["target"]).lower()
            if t in ctx.c2_flagged or c2ish:           # 표적 오기 보호: alert 기반 + technique 기반
                c2_protected.add(t)
            else:
                targets.add(t)
        # 표적 도메인은 attack 레코드가 이미 안다 → target_host + sample_uri 의 host
        th = str(a.get("target_host") or "").lower()
        if th and th != "unknown":
            (c2_protected if c2ish else thosts).add(th)   # C2 도메인(hadevatjulps.com) 보호
        # sample_uri 의 host 정체는 방향에 달렸다:
        #   actor 내부(밖을 공격) → host = 외부 피격자 → 표적이므로 제거 (단, c2 통신이면 C2 도메인)
        #   actor 외부(안을 공격) → host = 페이로드 배포 서버 → delivery IOC 이므로 보존
        host = str(a.get("sample_uri") or "").split("/", 1)[0].lower()
        if host and "." in host and not host.replace(".", "").replace(":", "").isdigit():
            if a["actor_scope"] == "internal":
                (c2_protected if c2ish else thosts).add(host)

    iocs = analysis.get("iocs", {})
    removed = []
    for bucket in ("c2", "delivery", "exfil"):
        kept = []
        for ip in iocs.get(bucket, []):
            if str(ip).lower() in targets:
                removed.append({"kind": "ip", "bucket": bucket, "value": ip,
                                "reason": "attack 표적 (피격자 — IOC 아님)"})
            else:
                kept.append(ip)
        iocs[bucket] = kept
    kept_doms = []
    for d in iocs.get("domains", []):
        if str(d).lower() in thosts:
            removed.append({"kind": "domain", "value": d,
                            "reason": "attack 표적 호스트 (피격자 — IOC 아님)"})
        else:
            kept_doms.append(d)
    iocs["domains"] = kept_doms
    if removed:
        analysis["_removed_attack_targets"] = removed
    if c2_protected:
        analysis["_c2_kept_despite_target_label"] = sorted(c2_protected)


def _add_to_bucket(analysis, bucket, values, tag):
    """승격기 공통 꼬리: 이미 어느 버킷에든 있으면 건너뛰고, 추가분은 _<tag> 로 노출(투명)."""
    iocs = analysis.setdefault("iocs", {})
    iocs.setdefault(bucket, [])
    have = {str(x).lower() for b in ("c2", "delivery", "exfil", "domains") for x in iocs.get(b, [])}
    added = [v for v in sorted(values) if v not in have]
    if added:
        iocs[bucket].extend(added)
        analysis.setdefault(tag, []).extend(added)


def attach_iocs_from_alerts(analysis, ctx):
    """위협-카테고리 alert 가 가리키는 '외부 관측 IP'를 iocs.c2 에 코드가 보장한다.

    LLM 이 근거·타임라인엔 C2 를 써놓고 정작 iocs.c2 는 비우는 문제(iocs.hashes 와 똑같은
    실패) 대응 — attach_hashes 와 같은 '코드가 안전 소유' 패턴.
      - 게이트는 threat_class(threat/rat) — 숫자 severity 가 아니다. ET CHAT Skype /
        FILE_SHARING Dropbox 는 sev1 이지만 benign 이라 승격 안 됨(q2 에서 실증한 오염).
      - 외부 관측 IP 만 대상, 공격 표적(피격자)은 제외.
      - 공유 CDN IP 는 make_policy 의 _is_cdn 이 IP-drop 에서 다시 걸러낸다(이중 안전).
    ground_iocs/annotate_attacks 뒤(승격 구간)에 돌려 제거 로직에 다시 안 지워지게 한다.
    """
    threat_ips = set()
    for a in ctx.tools.evidence.get("alerts", []):
        if not _is_threat_alert(a):
            continue
        for ip in (a.get("src_ips") or []) + (a.get("dst_ips") or []):
            s = str(ip).lower()
            if s in ctx.external_ips and s not in ctx.attack_targets:
                threat_ips.add(s)
    if threat_ips:
        _add_to_bucket(analysis, "c2", threat_ips, "_iocs_added_from_alerts")


def attach_iocs_from_dns(analysis, ctx):
    """의심 TLD(.su/.cc/.cyou/.xyz…) 관측 도메인 + 그 IP 를 iocs 에 코드가 보장 (탐지, 코드 소유).

    시그니처 없는 HTTPS-only 후속 C2/배포는 alert 가 안 걸려 attach_iocs_from_alerts 로도
    못 잡는다(실측: 20260131 의 holiday-forever.cc / communicationfirewall-security.cc).
    정상 서비스는 이런 TLD 를 거의 안 쓰므로 '의심 TLD + 피해자가 실제 연결한 IP(external.ips)로
    해석' 게이트만으로 고정밀 승격이 된다.
      - '탐지'일 뿐 '차단'이 아니다: CDN IP(예: Cloudflare)가 섞여도 make_policy 의 _is_cdn 이
        IP-drop 에서 걸러 도메인 룰로 돌린다(차단 안전은 enforcement 소유).
      - alert-IP 조인(도메인이 경보 IP 로 해석되면 악성)은 채택하지 않는다 — MS 연결테스트·
        Windows Update 가 INFO 경보를 받아 정상 도메인을 오탐(실측)하기 때문.
      - 내부 자산(호스트/AD 존)·공격표적 IP 는 제외(자폭 방지).
    """
    dom2ip = {}
    for d in ctx.tools.evidence.get("external", {}).get("domains", []) or []:
        q = str(d.get("query") or "").lower()
        if q:
            dom2ip[q] = [str(a).lower() for a in (d.get("answers") or []) if _IPV4.fullmatch(str(a))]

    mal = set()
    for q, ips in dom2ip.items():
        if ctx.is_internal_asset(q) or not SUSP_TLD.search(q):
            continue
        if any(i in ctx.external_ips for i in ips):     # 피해자가 실제 연결한 IP 로 해석
            mal.add(q)
    add_ip = set()
    for d in mal:                                        # 의심-TLD 확정 도메인의 IP 만 (benign 노이즈 배제)
        for i in dom2ip.get(d, []):
            if i not in ctx.internal_ips and i not in ctx.attack_targets:
                add_ip.add(i)
    if mal:
        _add_to_bucket(analysis, "domains", mal, "_iocs_added_from_dns_dom")
    if add_ip:
        _add_to_bucket(analysis, "c2", add_ip, "_iocs_added_from_dns_ip")


def attach_inbound_threat_ips(analysis, ctx):
    """인바운드 공격자 IP 를 iocs.c2 에 보장 (코드 소유). attach_iocs_from_alerts 는 external.ips
    (아웃바운드 dst 집계)만 봐서, 우리 서버를 때리는 외부 공격자를 놓친다 — 그 IP 는 인바운드라
    external.ips 에 없고 alert 의 src 로만 등장(실측: 20260315 웹공격의 45.148.10.66).
      - 방향 게이트: dst 에 내부가 있는 위협-카테고리 alert 의 '외부 출발지'만 승격. 아웃바운드
        malware C2 는 외부가 dst 라 이 조건에 안 걸려 기존 케이스에 영향 없음(수술적).
      - 공격표적(피격자)·이미 등록된 IP 는 제외.
    """
    cand = set()
    for a in ctx.tools.evidence.get("alerts", []):
        if not _is_threat_alert(a):
            continue
        if not ({str(d).lower() for d in (a.get("dst_ips") or [])} & ctx.internal_ips):
            continue                                     # 인바운드(내부를 향한) alert 만
        for ip in (a.get("src_ips") or []):
            s = str(ip).lower()
            if s and s not in ctx.internal_ips and s not in ctx.attack_targets and _IPV4.fullmatch(s):
                cand.add(s)
    if cand:
        _add_to_bucket(analysis, "c2", cand, "_iocs_added_inbound")


# 순서가 곧 규칙이다 — 앞 구간(정리/제거)이 끝난 뒤 뒤 구간(승격)이 돈다. 승격기를 제거기
# 앞에 두면 방금 넣은 IOC 를 제거기가 도로 지운다. 새 가드는 이 리스트에서 자리를 정한다.
PASSES = [
    # ── 정리/제거 구간 ──
    attach_identity,            # victims 정체(mac/hostname/username/role) 코드 확정
    demote_infra_victims,       # 인프라(DC/DNS)를 피해자로 오인 → 격리 자폭 방지
    attach_hashes,              # iocs.hashes 코드 확정 (업데이트 인프라 해시 제외)
    ground_iocs,                # iocs 오염/환각/내부자산 제거
    annotate_attacks,           # attacks scope 채움 + 표적을 iocs 에서 제거
    # ── 승격 구간 (제거 뒤여야 안 지워짐) ──
    attach_iocs_from_alerts,    # 위협-카테고리 alert 의 외부 IP → c2
    attach_iocs_from_dns,       # 의심 TLD 도메인 + IP (HTTPS-only 후속 C2)
    attach_inbound_threat_ips,  # 인바운드 공격자 IP
]


def apply_guards(analysis, tools):
    """forensic 결과에 코드 소유 후처리 전부 적용 (PASSES 순서)."""
    ctx = CaseContext(analysis, tools)
    for p in PASSES:
        p(analysis, ctx)
    return analysis


def code_triage(tools):
    """코드가 답을 아는 triage — threat/rat alert 나 멀웨어 후보 해시가 있으면 '사건 아님'일 수는
    없다(결정론적 사실). 3지선다에 LLM 사고 토큰(호출당 수 분)을 태우지 않고 생략한다.
    verdict 는 suspicious 바닥 — 확정 승급은 forensic+가드 뒤 upgrade_verdict(역시 코드)가 한다.
    조용한 캡처(신호 없음)만 LLM triage 로 간다 — no_incident 야말로 판단이 필요한 곳이므로."""
    reasons = []
    threat = [a for a in tools.evidence.get("alerts", []) if is_threat_alert(a)]
    if threat:
        reasons.append(f"위협 카테고리 alert {len(threat)}종 — 예: {(threat[0].get('signature') or '')[:60]}")
    mal = tools.malware_candidate_hashes()["malware"]
    if mal:
        reasons.append(f"멀웨어 후보 해시 {len(mal)}개 (업데이트 인프라 서빙분 제외 후)")
    if not reasons:
        return None
    print(f"[triage] 코드 판정 — LLM triage 생략: {reasons[0]}")
    return {"verdict": "suspicious",
            "grounds": ["[코드 판정 — LLM triage 생략] " + r for r in reasons]}


def upgrade_verdict(out, analysis):
    """suspicious → confirmed 승급 (결정론): 가드를 전부 통과한 최종 분석에 '침해 확정 호스트'와
    'IOC(c2 또는 해시)'가 함께 남아 있으면 사건은 확정이다. code_triage 의 바닥값 보정이자,
    LLM triage 가 소심하게 suspicious 로 남긴 것(2024-11-26 NetSupport 실증)의 교정."""
    if out.get("verdict") != "suspicious" or not analysis:
        return
    compromised = [v for v in analysis.get("victims", []) if v.get("status") == "compromised"]
    iocs = analysis.get("iocs", {})
    if compromised and (iocs.get("c2") or iocs.get("hashes")):
        out["verdict"] = "confirmed"
        out["grounds"].append(f"[코드 승급] 침해 확정 호스트 {len(compromised)}대 + "
                              f"c2 {len(iocs.get('c2') or [])}건/해시 {len(iocs.get('hashes') or [])}건 "
                              f"— suspicious → confirmed")


def floor_report(tools):
    """코드-only 바닥 보고서 (LLM 0회) — 판결문 P0-2 의 상설 베이스라인.
    이후 모든 성능 표는 [코드-only / +LLM] 비교 형식으로만 인용한다.
    - verdict: code_triage 신호 있으면 suspicious(가드 뒤 upgrade 가능), 없으면 no_incident.
    - victims 는 채우지 않는다 — 침해 '판정'은 코드 소관이 아니라는 원칙 유지
      (host_deviations 를 판정으로 승격하는 과잉은 레드팀 심사에서 기각된 codex 안).
    - iocs 는 승격기(알럿/의심TLD/인바운드)가 채우고 가드가 정제 — 즉 floor 의 IOC 성적이
      곧 "LLM 없이 어디까지"이며, LLM 행과의 차이가 곧 LLM 의 순기여(발견 장부의 분모)다."""
    res = code_triage(tools)
    if res is None:
        return {"verdict": "no_incident",
                "grounds": ["[코드 바닥] 위협 카테고리 alert·멀웨어 후보 해시 없음"],
                "pipeline_status": "ok", "_mode": "floor"}, None
    analysis = {"victims": [], "attacks": [],
                "iocs": {"c2": [], "delivery": [], "exfil": [], "domains": [], "hashes": []},
                "timeline": [], "patient_zero": "",
                "executive_summary": "(코드-only 바닥 — LLM 분석 없음)",
                "anomaly_analysis": [], "assessment": "코드 결정론 신호만 반영된 바닥 보고서."}
    apply_guards(analysis, tools)
    out = {"verdict": res["verdict"], "grounds": res.get("grounds", []),
           "pipeline_status": "ok", "_mode": "floor", "analysis": analysis}
    upgrade_verdict(out, analysis)
    return out, analysis


def main():
    # 1. 인자: <case> [--fresh|--replay]
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    if not args:
        raise SystemExit("사용법: python3 run.py <case> [--floor|--fresh|--replay]\n"
                         "  --floor: 코드-only 바닥 (LLM 0회, 수 초) → reports/floor/<case>.json\n"
                         "  (기본 auto: evidence 동일하면 forensic 캐시 재생 — 코드 수정 반복 가속)\n"
                         "  --fresh: 항상 LLM 재호출  |  --replay: LLM 절대 호출 안 함(캐시만, 로컬 가능)")
    filename = args[0]
    fmode = ("floor" if "--floor" in flags else
             "replay" if "--replay" in flags else ("fresh" if "--fresh" in flags else "auto"))

    # 2. TOOLS 클래스 생성
    tools = Tools(filename)

    # 코드-only 바닥 (LLM 0회, 수 초) — reports/floor/ 에 별도 저장해 LLM 행과 나란히 채점
    if fmode == "floor":
        out, _ = floor_report(tools)
        ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        fdir = os.path.join(ROOT, "reports", "floor")
        os.makedirs(fdir, exist_ok=True)
        path = os.path.join(fdir, f"{filename}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        print(f"[floor] verdict={out['verdict']}  c2={len((out.get('analysis') or {}).get('iocs', {}).get('c2', []))}건")
        print(f"[report] 코드-only 바닥 → {path}")
        return

    # 3. triage → (에스컬레이션 시) forensic. 모든 결과를 하나의 JSON 으로.
    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    outdir = os.path.join(ROOT, "reports")
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, f"{filename}.json")

    def fail(stage, err):
        # LLM 호출 실패 = 판정 없음. 지어내지 않고 실패를 보고서로 남긴다 (verdict=null).
        #   노트북/make_policy/render 는 pipeline_status 를 보고 건너뛴다.
        out = {"verdict": None, "grounds": [f"{stage} LLM 호출 실패: {err}"],
               "pipeline_status": f"llm_error:{stage}"}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        print(f"[main] {stage} 실패 — {err}\n[report] 실패 기록 → {path}")
        sys.exit(1)

    res = code_triage(tools)          # 코드가 답을 아는 경우 LLM triage 생략 (사고 토큰 수 분 절약)
    if res is None:
        if fmode == "replay":
            # replay 는 LLM 을 안 쓴다. 조용한 캡처의 triage 판단은 못 하므로 suspicious 바닥
            #   (캐시된 forensic 이 있으면 어차피 에스컬레이트된 케이스 — 가드/승급이 재구성).
            res = {"verdict": "suspicious", "grounds": ["[replay] LLM triage 생략 — suspicious 바닥"]}
        else:
            try:
                res = triage(tools)
            except LLMError as ex:
                fail("triage", ex)
    out = {"verdict": res["verdict"], "grounds": res.get("grounds", []),
           "pipeline_status": "ok"}          # 부분 산출물(파싱 실패)과 완전 산출물을 구분

    if res["verdict"] == "no_incident":
        # 무혐의: 분석 chat 안 감 (사건 전제 프레이밍 차단)
        print("=== 판정: 이상 없음 ===")
        for g in out["grounds"]:
            print(f"  - {g}")
        print("잔여 리스크: 본 판정은 시그니처+행동 휴리스틱 커버리지 내에서만 유효함.")
    else:
        try:
            analysis = forensic(tools, fmode)
        except LLMError as ex:
            fail("forensic", ex)
        if analysis:
            apply_guards(analysis, tools)
            upgrade_verdict(out, analysis)   # 결정론 승급 (suspicious 바닥 → confirmed)
            out["analysis"] = analysis
            print(json.dumps(analysis, ensure_ascii=False, indent=2))
        else:
            out["pipeline_status"] = "forensic_parse_failed"
            print("[main] 분석 JSON 생성 실패 — verdict 만 저장 (pipeline_status=forensic_parse_failed)")

    # 4. JSON 저장 (채점/렌더링 공통 입력)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"[report] 저장됨 → {path}")


if __name__ == "__main__":
    main()
