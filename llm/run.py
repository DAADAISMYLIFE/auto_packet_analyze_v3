import sys, json, re, os

from tools import Tools
from ollama import chat
from config import (MODEL, OPTS, VERDICT_SCHEMA, REPORT_SCHEMA,
                    SYSTEM_PROMPT_TRIAGE, SYSTEM_PROMPT_FORENSIC)

# IOC 값에서 진짜 IP/도메인 토큰만 뽑는 정규식 (LLM 장식·JSON 누출 제거용)
_IPV4 = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
_DOMAIN = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?")

def triage(tools):
    tier1_evidence = json.dumps({
        "meta": tools.get_meta(),
        "hosts": tools.get_hosts_info(),
        "alerts" : tools.get_alerts(),
        "external" : tools.get_external(),
        "http" : tools.get_http(),
        "files" : tools.get_files(),
        "lateral_movement" : tools.get_lateral_movement(),
        "anomalies" : tools.get_anomalies()
    }, ensure_ascii=False, default=str)

    res = chat(model=MODEL, format=VERDICT_SCHEMA,   # ← format이 강제 선택
            think=False,                              # thinking 끔: content가 바로 JSON, 추론토큰이 예산 안 먹음
            messages=[{"role": "system", "content": SYSTEM_PROMPT_TRIAGE},
                        {"role": "user", "content": "Triage this capture.\n\n# Tier-1 Evidence\n" + tier1_evidence}],
            options=OPTS
            )

    content = res.message.content
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # grounds 폭주로 JSON 이 잘려도 verdict 는 맨 앞이라 살아있음 → 정규식으로 복구
        m = re.search(r'"verdict"\s*:\s*"(no_incident|suspicious|confirmed)"', content)
        if m:
            print(f"[triage] JSON 잘림 — verdict 복구: {m.group(1)}")
            return {"verdict": m.group(1),
                    "grounds": ["(grounds 폭주로 잘림 — verdict 만 복구)"]}
        print("[triage] verdict 복구 실패 — suspicious 폴백")
        print("  content(repr):", repr(content[:200]))   # 비었나/뭐가왔나 진단용
        print("  thinking 있었나:", bool(getattr(res.message, "thinking", None)))
        return {"verdict": "suspicious",
                "grounds": ["triage 출력 파싱 실패 — 안전을 위해 분석 단계로 에스컬레이트"]}

def forensic(tools):
    # tier1 정보 주입 (claude_llm 검증: tier1 만으로 충분 → tool 루프 없이 단일 호출)
    tier1_evidence = json.dumps({
        "meta": tools.get_meta(),
        "hosts": tools.get_hosts_info(),
        "alerts" : tools.get_alerts(),
        "external" : tools.get_external(),
        "http" : tools.get_http(),
        "files" : tools.get_files(),
        "lateral_movement" : tools.get_lateral_movement(),
        "anomalies" : tools.get_anomalies()
    }, ensure_ascii=False, default=str)

    # format 강제 → 마크다운 산문이 아니라 REPORT_SCHEMA JSON 을 그대로 받는다
    res = chat(model=MODEL, format=REPORT_SCHEMA, think=False,
               messages=[{"role": "system", "content": SYSTEM_PROMPT_FORENSIC},
                         {"role": "user",
                          "content": "Analyze this incident and return the structured JSON."
                                     "\n\n# Tier-1 Evidence\n" + tier1_evidence}],
               options=OPTS)
    try:
        return json.loads(res.message.content)
    except (json.JSONDecodeError, TypeError):
        print("[forensic] 구조화 JSON 파싱 실패 — content(repr):",
              repr((res.message.content or "")[:300]))
        return None

def attach_identity(analysis, tools):
    """victims[] 의 ip 조인 정체(mac/hostname/username)와 patient_zero 를 코드가 확정.

    mac/hostname/username 은 LLM 이 hosts[] 에서 베끼는 값이라 두 사고가 난다:
      (1) 전사 손상 — 'CFA3467' 류 hostname 오염, mac 오염.
      (2) 통째 생략 — 스키마 optional 이라 format 강제 gemma 가 곧잘 빼먹음.
    또 LLM 은 ip/patient_zero 에 설명을 덧붙이기도 한다
    ('10.6.15.119 (First observed...)') → clean_ip 로 IP 토큰만 뽑아 정규화.
    ip 만 앵커로 쓰고 정체는 코드가 evidence 로 덮어쓴다(없으면 None, 환각 제거).
    """
    by_ip = {h.get("ip"): h for h in tools.evidence.get("hosts", [])}
    host_ips = set(by_ip)

    def clean_ip(v):
        # 장식 붙은 값에서 IP 토큰만 — 내부 호스트 IP 를 우선 선택
        ips = _IPV4.findall(str(v or ""))
        return next((i for i in ips if i in host_ips), ips[0] if ips else v)

    for v in analysis.get("victims", []):
        v["ip"] = clean_ip(v.get("ip"))
        h = by_ip.get(v["ip"]) or {}
        v["mac"] = h.get("mac")
        v["hostname"] = h.get("hostname")
        v["username"] = h.get("username")
    if analysis.get("patient_zero"):
        analysis["patient_zero"] = clean_ip(analysis["patient_zero"])

def attach_hashes(analysis, tools):
    """iocs.hashes 를 evidence 의 malware-candidate 파일에서 코드가 채운다 (해시 블라인드니스 방지).

    LLM 은 files[] 를 보고도 hashes 를 거의 항상 [] 로 낸다 → 코드가 확정값으로 덮어쓴다.
    ms-pol(정상 GPO) + 업데이트 인프라(windowsupdate 등)가 서빙한 x-dosexec 은 serving-host
    조인으로 제외한다 (MS Defender 업데이트 해시를 차단정책에 넣던 오탐 차단).
    제외분은 침묵하지 않고 _excluded_benign_hashes 로 노출(투명).
    """
    res = tools.malware_candidate_hashes()
    analysis.setdefault("iocs", {})["hashes"] = res["malware"]
    if res["benign_excluded"]:
        analysis["_excluded_benign_hashes"] = res["benign_excluded"]

def ground_iocs(analysis, tools):
    """iocs 의 IP/도메인을 evidence 관측집합과 exact-match 대조해 오염/환각을 제거한다.
    (차단정책 안전장치 — 오염된 IP 로 깨진 Snort 룰이 나가는 것을 원천 차단.)

    - 복원은 안 함: '1para.36.191.35' 를 '194.36.191.35' 로 추측하지 않는다(추측이
      틀리면 정상 서버 차단 위험). evidence 에 없으면 그냥 제거.
    - 도메인은 suffix 허용: 'mail.staroxalate.com' 은 'staroxalate.com' 관측으로 인정.
    - IP 버킷(c2/delivery/exfil)에 URL(host/path)이나 도메인이 잘못 담기면 host 만
      떼어 관측 도메인일 때 domains 로 이관(salvage) — gemma 의 버킷 오배치 구제.
    - 제거분은 조용히 버리지 않고 _rejected_iocs 로 노출(사람 검토용).
    - hashes 는 이미 attach_hashes 가 evidence 에서 코드로 채우므로 건드리지 않는다.
    """
    obs = tools.observed_iocs()

    def host_of(v):
        # LLM 이 IP/도메인에 붙이는 오염을 벗겨 진짜 토큰만 추출:
        #   'host/path'(경로), '1.2.3.4 (HTTP Beacon)'(주석), "dom.com']},"(JSON 누출) 등.
        # obs 대조는 그대로라 환각·손상 오타는 여전히 탈락(안전) — 값을 '추측 복원'하지는 않음.
        s = str(v).split("/", 1)[0].strip().lower()
        m = _IPV4.search(s)
        if m:
            return m.group(0)
        m = _DOMAIN.search(s)
        return m.group(0) if m else s

    def dom_ok(d):
        d = d.lower()
        return any(d == o or d.endswith("." + o) or o.endswith("." + d) for o in obs["domains"])

    iocs = analysis.get("iocs", {})
    rejected = []
    salvaged_doms = []          # IP 버킷에 잘못 담긴 도메인 → domains 로 이관
    for bucket in ("c2", "delivery", "exfil"):
        kept = []
        for ip in iocs.get(bucket, []):
            host = host_of(ip)
            if host in obs["ips"]:
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
        if not host or host in seen:
            continue
        if dom_ok(host):
            seen.add(host)
            kept_doms.append(host)
        else:
            rejected.append({"kind": "domain", "value": d,
                             "reason": "evidence 미관측 (오염/환각)"})
    iocs["domains"] = kept_doms
    if rejected:
        analysis["_rejected_iocs"] = rejected

def annotate_attacks(analysis, tools):
    """attacks[] 후처리 (코드 소유):

      1. actor_scope/target_scope 를 host inventory 로 채운다 — 내부/외부는
         evidence.hosts 유무로 결정론적. 차단 반응 분기의 근거가 된다:
           actor internal → 침해된 발판일 수 있음(RCE/pivot) → 호스트 격리 대상
           actor external → 외부 공격자 → 경계에서 IP 차단 대상
      2. target(피격자)은 IOC 가 아니므로 iocs(c2/delivery/exfil/domains)에서 제거.
         스키마에 attacks.target 칸을 줬어도 gemma 가 습관적으로 c2 에 또 넣을 수 있어
         코드가 최종적으로 빼낸다(ground_iocs 와 같은 '코드가 안전을 소유' 원칙).
         자기/피해 서버를 차단정책이 막는 자폭 방지. 제거분은 _removed_attack_targets 로 노출.
    """
    attacks = analysis.get("attacks") or []
    if not attacks:
        return
    internal = {str(h.get("ip")).lower() for h in tools.evidence.get("hosts", []) if h.get("ip")}

    def scope(ip):
        if not ip:
            return "unknown"
        return "internal" if str(ip).lower() in internal else "external"

    targets, thosts = set(), set()
    for a in attacks:
        a["actor_scope"] = scope(a.get("actor"))       # 코드가 확정 (LLM 값 덮어씀)
        a["target_scope"] = scope(a.get("target"))
        if a.get("target"):
            targets.add(str(a["target"]).lower())
        # 표적 도메인은 attack 레코드가 이미 안다 → target_host + sample_uri 의 host
        th = str(a.get("target_host") or "").lower()
        if th and th != "unknown":
            thosts.add(th)
        # sample_uri 의 host 정체는 방향에 달렸다:
        #   actor 내부(밖을 공격) → host = 외부 피격자 → 표적이므로 제거
        #   actor 외부(안을 공격) → host = 페이로드 배포 서버 → delivery IOC 이므로 보존
        host = str(a.get("sample_uri") or "").split("/", 1)[0].lower()
        if host and "." in host and not host.replace(".", "").replace(":", "").isdigit():
            if a["actor_scope"] == "internal":
                thosts.add(host)

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

def create_rules(tools):
     
     analyzing_report = "보고서 json 파일 읽기"
     
     res = chat(model=MODEL, format="SNORT패턴 만들기",   # ← format이 강제 선택
            think=True,                              # thinking 끔: content가 바로 JSON, 추론토큰이 예산 안 먹음
            messages=[{"role": "system", "content": SYSTEM_PROMPT_TRIAGE},
                        {"role": "user", "content": "뭐시기 저시기\n\n# Analayze\n" + tier1_evidence}],
            options=OPTS
            )

def main():
    # 1. 매개변수로 어떤 evidence파일인지 입력 받기
    if len(sys.argv) < 2:
        raise SystemExit("사용법: python3 run.py <output/ 아래 evidence 폴더명>")
    filename = sys.argv[1]

    # 2. TOOLS 클래스 생성
    tools = Tools(filename)

    # 3. triage → (에스컬레이션 시) forensic. 모든 결과를 하나의 JSON 으로.
    res = triage(tools)
    out = {"verdict": res["verdict"], "grounds": res.get("grounds", [])}

    if res["verdict"] == "no_incident":
        # 무혐의: 분석 chat 안 감 (사건 전제 프레이밍 차단)
        print("=== 판정: 이상 없음 ===")
        for g in out["grounds"]:
            print(f"  - {g}")
        print("잔여 리스크: 본 판정은 시그니처+행동 휴리스틱 커버리지 내에서만 유효함.")
    else:
        analysis = forensic(tools)
        if analysis:
            attach_identity(analysis, tools)
            attach_hashes(analysis, tools)
            ground_iocs(analysis, tools)       # iocs 오염/환각 제거 (차단정책 안전장치)
            annotate_attacks(analysis, tools)  # attacks scope 채움 + 표적을 iocs 에서 제거
            out["analysis"] = analysis
            print(json.dumps(analysis, ensure_ascii=False, indent=2))
        else:
            print("[main] 분석 JSON 생성 실패 — verdict 만 저장")

    # 4. JSON 저장 (채점/렌더링 공통 입력)
    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    outdir = os.path.join(ROOT, "reports")
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, f"{filename}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"[report] 저장됨 → {path}")

    # 5. TODO(다음 단계): reports/<name>.json → Snort 차단 룰 생성.
    #    LLM chat() 이 아니라 별도 코드 모듈로 — iocs 재전사 오염 방지(합의됨).
    #    아래 create_rules 스텁은 미사용(format/think 오류 + tier1_evidence 미정의).

    # 6. TODO : 보고서 만들기

if __name__ == "__main__":
    main()
