#!/usr/bin/env python3
"""
차단정책 생성 (파이프라인 5단계): reports/<name>.json → Suricata drop 룰.

  python3 scripts/make_policy.py <name> [--validate]
    입력:  reports/<name>.json   (분석 산출물, iocs 이미 정제됨)
    출력:  reports/<name>.rules  (Suricata 룰)

원칙(대화에서 확정):
  - chat() 없음. 정제된 IOC 를 룰 템플릿에 결정론적으로 끼워넣기만 → 재오염 방지.
    같은 report → 같은 룰/sid (sort+dedup) 라 재실행·diff 안전.
  - 안전은 상류에서 이미 보장: 피격자(attacks.target)·내부 자산은
    annotate_attacks/ground_iocs 가 이미 iocs 에서 제거했다 → 여기 남은 IP/도메인은
    '진짜 외부 악성'으로 신뢰하고 룰로 만든다.
  - scope 분기: 외부 actor = IP 차단 / 내부 actor = 호스트 격리 / target = 룰 없음.
  - 각 값은 형식검증(유효 IPv4 / 도메인) 통과분만 룰화 — 깨진 값이 룰로 새는 것 방지.
  - 해시는 보류(사용자 결정 대기).
"""
import sys, os, json, re, subprocess, ipaddress

SID_BASE = 1000000
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_DOM = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)*\.[a-z]{2,}$", re.I)


def _valid_ip(s):
    if not _IPV4.match(str(s)):
        return False
    return all(0 <= int(o) <= 255 for o in str(s).split("."))


# 공유 CDN 엣지 대역 (사업자 공시 소유대역). 이 IP 는 수천 사이트가 공유하는 엣지라
# drop ip 로 막으면 Cloudflare/Fastly 전체가 막힌다(부수피해). 악성 '도메인'은
# tls.sni/dns.query 룰이 공유 IP 위에서도 그 호스트만 정확히 잡으므로, CDN IP 는
# IP차단에서 빼고 도메인 룰에 맡긴다. (Cloudflare: cloudflare.com/ips-v4, Fastly 주대역)
_CDN_NETS = [ipaddress.ip_network(c) for c in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",   # ── Cloudflare
    "151.101.0.0/16",                                     # ── Fastly
)]


def _is_cdn(ip):
    try:
        return any(ipaddress.ip_address(ip) in n for n in _CDN_NETS)
    except ValueError:
        return False


def _priv(ip):
    """사설(내부) IPv4 여부. 외부 IP 를 격리룰로 잘못 내보내는 것 방지."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def make_rules(report):
    """report → (rules[list[str]], skipped[list[(kind,value)]]). 순수 함수, 결정론."""
    a = report.get("analysis") or {}
    iocs = a.get("iocs", {})
    attacks = a.get("attacks") or []
    victims = a.get("victims") or []

    # 인프라(DC/DNS)는 자동 격리 대상에서 제외 — DC 를 drop any->any 로 끊으면 AD 전체가
    # 서비스 자폭. 인프라는 '패치·조사' 대상이지 격리 대상이 아니며, 보고서에 compromised 로
    # 남아 사람이 판단한다(프로젝트 목표: 최종 o/x 는 사람). role 은 run.py 가 evidence 로 확정.
    role_of = {str(v.get("ip")): v.get("role") for v in victims if v.get("ip")}
    def _is_infra(ip):
        return bool(ip) and role_of.get(str(ip)) in ("domain_controller", "dns_server")

    block_ips = {ip for b in ("c2", "delivery", "exfil") for ip in iocs.get(b, [])}
    block_ips |= {t["actor"] for t in attacks
                  if t.get("actor_scope") == "external" and t.get("actor")}
    isolate = {t["actor"] for t in attacks
               if t.get("actor_scope") == "internal" and t.get("actor") and not _is_infra(t["actor"])}
    # 침해 확정된 내부 호스트도 격리(공격자든 워크스테이션 타겟이든). 외부 IP 오분류 방어로
    # 사설대역만. 단 인프라(DC/DNS)는 제외 — 위 자폭 방지.
    isolate |= {v["ip"] for v in victims
                if v.get("status") == "compromised" and _priv(v.get("ip") or "")
                and not _is_infra(v.get("ip"))}
    # 인프라라서 격리에서 뺀 침해 호스트는 침묵하지 않고 사유를 남긴다(사람 검토 유도)
    infra_skipped = [(str(v.get("ip")), v.get("role")) for v in victims
                     if v.get("status") == "compromised" and _priv(v.get("ip") or "")
                     and _is_infra(v.get("ip"))]
    block_ips -= isolate                       # 내부 호스트는 IP차단 아니라 격리 룰로만
    block_doms = set(iocs.get("domains", []))

    rules, sid, skipped = [], SID_BASE, []
    for ip, role in infra_skipped:             # 인프라 격리 제외분 노출 (사람 검토: 패치/조사)
        skipped.append((f"isolate-infra:{role}(패치/조사대상)", ip))
    cdn_ips = {ip for ip in block_ips if _valid_ip(ip) and _is_cdn(ip)}
    block_ips -= cdn_ips                        # ── 공유 CDN 엣지: IP-drop 제외(부수피해 방지) ──
    for ip in sorted(cdn_ips):                  #    조용히 버리지 않고 사유를 남긴다(도메인룰이 대체)
        tag = "cdn-ip:도메인룰로대체" if block_doms else "cdn-ip:!경고-막을도메인없음-수동확인"
        skipped.append((tag, ip))
    for ip in sorted(block_ips):               # ── 외부 악성 IP: 아웃바운드 drop ──
        if not _valid_ip(ip):
            skipped.append(("ip", ip)); continue
        rules.append(f'drop ip $HOME_NET any -> {ip} any '
                     f'(msg:"[AUTO] BLOCK ioc {ip}"; classtype:trojan-activity; '
                     f'sid:{sid}; rev:1;)'); sid += 1
    for dom in sorted(block_doms):             # ── 도메인: DNS 조회 + TLS SNI 둘 다 ──
        d = str(dom).lower()
        if not _DOM.match(d):
            skipped.append(("domain", dom)); continue
        rules.append(f'drop dns $HOME_NET any -> any any '
                     f'(msg:"[AUTO] BLOCK dns {d}"; dns.query; content:"{d}"; nocase; '
                     f'sid:{sid}; rev:1;)'); sid += 1
        rules.append(f'drop tls $HOME_NET any -> any any '
                     f'(msg:"[AUTO] BLOCK sni {d}"; tls.sni; content:"{d}"; nocase; '
                     f'sid:{sid}; rev:1;)'); sid += 1
    for host in sorted(isolate):               # ── 내부 침해 발판: 호스트 격리 ──
        if not _valid_ip(host):
            skipped.append(("isolate", host)); continue
        rules.append(f'drop ip {host} any -> any any '
                     f'(msg:"[AUTO] ISOLATE compromised host {host}"; sid:{sid}; rev:1;)'); sid += 1
    # 해시: 보류 (Suricata filesha256 은 평문HTTP 한정 + 전송완료 후 판정 → EDR 병행이 맞아 대기)
    return rules, skipped


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2 (content) — IP 무관 행위 시그니처.
#   장비가 IP 를 any/any 로 다루고 공격자 IP 는 로테이션되므로, 경로·UA·바디 같은
#   '안 바뀌는 바이트'로 잡는다. 관측 샘플에서 불변부(LCS) 추출 + 가변부(랜덤 ID) 게이팅
#   + 공격클래스(vetted 패턴) 매핑. chat() 없음 — 전부 결정론. 기본 alert(오탐 무해),
#   고신뢰(다중샘플 경로)만 drop. 경로/UA/바디는 report 에 없으므로 evidence 를 직접 읽는다.
# ─────────────────────────────────────────────────────────────────────────────
S2_SID_BASE = 1100000

_TOOL_UA = ("powershell", "netsupport", "dyngate", "curl", "wget", "python", "winhttp",
            "go-http", "libwww", "okhttp", "java/", "requests")
_BROWSER_UA = ("applewebkit", "gecko/", "trident", "msie", "chrome/", "firefox/",
               "safari/", "edg/", "presto", "opera")
_BENIGN_UA = ("microsoft ncsi", "microsoft-cryptoapi", "windows-update", "microsoft-delivery",
              "google update", "microsoft bits", "ms-webservices", "wsdapi", "wsd server",
              "dafupnp", "teamviewer")
_BENIGN_DOM = ("microsoft.com", "windows.com", "msn.com", "live.com", "office.com", "office365.com",
               "google.com", "gstatic.com", "googleapis.com", "adobe.com", "mozilla.org",
               "windowsupdate.com", "msftconnecttest.com", "digicert.com", "verisign.com",
               "teamviewer.com", "ipify.org", "bing.com", "skype.com")
_GENERIC_PATH = {"/", "/index.php", "/index.html", "/favicon.ico", "/connecttest.txt",
                 "/ncsi.txt", "/robots.txt"}
# 공격클래스 = 샘플로 정규식을 만들지 않고, 알려진 클래스에 vetted 패턴을 붙인다.
_ATTACK = (
    ("SQLi-tautology", r'(?i)(\x27|%27)\s*(or|and)\s*(\x27|%27)?[\w]+\s*=\s*(\x27|%27)?[\w]+',
     lambda s: bool(re.search(r"(?i)(\x27|%27|')\s*(or|and)\b.{0,12}=", s))),
    ("SQLi-union", r'(?i)union(\s|%20|\+|/\*)+select',
     lambda s: "union" in s.lower() and "select" in s.lower()),
    ("path-traversal", r'(\.\./|\.\.%2f|%2e%2e/)',
     lambda s: "../" in s or "%2e%2e" in s.lower()),
    ("cmd-injection", r'(?i)(;|\||%3b|%7c)\s*(wget|curl|bash|/bin/|cmd(\.exe)?|powershell|nc )',
     lambda s: bool(re.search(r"(?i)[;|]\s*(wget|curl|/bin/|cmd|powershell|nc )", s))),
    ("xss", r'(?i)(<script|%3cscript|javascript:)',
     lambda s: "<script" in s.lower() or "%3cscript" in s.lower()),
)


def _ua_kind(ua):
    if not ua or ua == "None":
        return "none"
    u = ua.lower()
    if any(t in u for t in _TOOL_UA):
        return "tool"
    if any(b in u for b in _BENIGN_UA):
        return "benign"
    if any(b in u for b in _BROWSER_UA):
        return "browser"
    return "unknown"


def _ua_token(ua):
    m = re.search(r'([A-Za-z][\w .-]*?(?:PowerShell|NetSupport Manager|DynGate|curl|Wget|'
                  r'python-requests|WinHTTP)[\w./-]*)', ua, re.I)
    return m.group(1).strip() if m else ua.strip()[:40]


def _parse_url(url):
    """잡음 내성(스킴/중복호스트 방어). url → (host, path, query)."""
    u = url.split("://")[-1]
    host, _, rest = u.partition("/")
    return host, "/" + rest.split("?", 1)[0], (rest.split("?", 1)[1] if "?" in rest else "")


def _host0(h):
    return (h or "").split(":")[0]


def _benign_dom(d):
    d = _host0(d).lower()
    return any(d == b or d.endswith("." + b) for b in _BENIGN_DOM)


def _lcs2(a, b):
    m = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    best = end = 0
    for i in range(len(a)):
        for j in range(len(b)):
            if a[i] == b[j]:
                m[i + 1][j + 1] = m[i][j] + 1
                if m[i + 1][j + 1] > best:
                    best = m[i + 1][j + 1]; end = i + 1
    return a[end - best:end]


def _lcs(ss):
    cur = ss[0]
    for s in ss[1:]:
        cur = _lcs2(cur, s)
        if not cur:
            break
    return cur


def _path_ok(p):
    if p in _GENERIC_PATH or len(p) < 6:
        return False
    if re.fullmatch(r'/[a-z]{1,3}/?', p):   # /de/ /en/ 류 너무 짧아 오탐
        return False
    return True


def _seg_random(seg):
    """경로 세그먼트가 랜덤 ID(재출현 안 함)인가 — content 부적합 판정용."""
    s = re.sub(r'[._+-]', '', seg)
    if len(s) < 6:
        return False
    if re.fullmatch(r'[0-9]+', s):                                   # 숫자 시리얼
        return len(s) >= 6
    up, lo, dig = re.search('[A-Z]', s), re.search('[a-z]', s), len(re.findall(r'\d', s))
    if len(s) >= 8 and up and lo:                                    # 대소문자 혼합 = base62 ID
        return True
    if len(s) >= 12 and dig >= 6:                                    # 숫자 다수 = per-victim ID
        return True
    return False


def _looks_random(lit):
    if re.search(r'[0-9a-fA-F]{16,}', lit):                          # 16자+ hex 해시 최우선
        return True
    return any(_seg_random(s) for s in re.split(r'[/&?=]', lit) if s)


def _sc(s):
    """Suricata content 문자열 이스케이프( " ; \\ | 및 비출력 → |xx| )."""
    out, hx = [], []

    def flush():
        if hx:
            out.append("|" + " ".join(hx) + "|"); hx.clear()

    for ch in s:
        if 0x20 <= ord(ch) < 0x7f and ch not in '"\\;|':
            flush(); out.append(ch)
        else:
            for b in ch.encode("utf-8"):
                hx.append("%02x" % b)
    flush()
    return "".join(out)


def content_rules(evidence, block_ips=None, block_doms=None, sid_base=S2_SID_BASE):
    """evidence.json → SECTION 2 content 룰 list.

    악성 http flow 식별 트리거(독립 3종):
      ①report 의 grounded IOC(dst∈block_ips / host∈block_doms) ②비브라우저 도구 UA
      ③공격클래스 페이로드(방향 무관). report 없이 실행되면 alert(sev≤2, INFO 제외) 로 폴백.
    """
    ext = evidence.get("external") or {}
    https = ext.get("http") or []
    hosts = evidence.get("hosts") or []
    alerts = evidence.get("alerts") or []

    def _ext(ip):
        return bool(ip) and _valid_ip(ip) and not _priv(ip)

    bad = {str(x) for x in (block_ips or [])}
    if not bad:                                    # 폴백: report 없이 evidence 만으로
        for al in alerts:
            if (al.get("severity") or 9) <= 2 and not re.match(r'ET (INFO|POLICY|DNS|HUNTING)',
                                                               al.get("signature", "")):
                bad |= {ip for ip in (al.get("dst_ips") or []) if _ext(ip)}
    bad_doms = {str(d).lower() for d in (block_doms or [])}

    mal = []
    for h in https:
        host, path, query = _parse_url(h.get("url", ""))
        ua = h.get("user_agent") or ""
        body = h.get("req_body") or ""
        dst = h.get("dst_ip") or ""
        blob = path + "?" + query + " " + (body if body != "None" else "")
        hit = (any(det(blob) for _, _, det in _ATTACK)
               or (_ext(dst) and dst in bad)
               or (_host0(host).lower() in bad_doms)
               or (_ext(dst) and _ua_kind(ua) == "tool"))
        if hit:
            mal.append(dict(host=_host0(host), path=path, query=query, ua=ua, body=body))

    rules, sid, seen = [], sid_base, set()

    # (a) 경로 지문: 호스트별 → 첫 세그먼트 클러스터 → LCS → 랜덤 게이트
    byhost = {}
    for f in mal:
        if _path_ok(f["path"]):
            byhost.setdefault(f["host"], []).append(f["path"])
    for host in sorted(byhost):
        clusters = {}
        for p in set(byhost[host]):
            clusters.setdefault(p.strip("/").split("/")[0], []).append(p)
        for seg in sorted(clusters):
            ps = sorted(set(clusters[seg]))
            lit = (_lcs(ps) if len(ps) >= 2 else ps[0]).rstrip()
            if not _path_ok(lit) or lit in seen or _looks_random(lit):
                continue
            seen.add(lit)
            act = "drop" if (len(lit) >= 10 and len(ps) >= 2) else "alert"
            rules.append(f'{act} tcp any any -> any any (msg:"[AUTO][S2] distinctive URI path"; '
                         f'flow:to_server,established; content:"{_sc(lit)}"; offset:4; '
                         f'depth:{min(len(lit) + 8, 90)}; nocase; classtype:trojan-activity; '
                         f'sid:{sid}; rev:1;)'); sid += 1

    # (b) 비브라우저 UA 지문
    seen_ua = set()
    for f in mal:
        if _ua_kind(f["ua"]) != "tool":
            continue
        tok = _ua_token(f["ua"])
        if tok.lower() in seen_ua or len(tok) < 5:
            continue
        seen_ua.add(tok.lower())
        rules.append(f'alert tcp any any -> any any (msg:"[AUTO][S2] non-browser User-Agent"; '
                     f'flow:to_server,established; content:"User-Agent|3a| "; nocase; '
                     f'content:"{_sc(tok)}"; distance:0; nocase; sid:{sid}; rev:1;)'); sid += 1

    # (c) POST 바디 파라미터 집합 지문 (케이스당 1)
    for f in mal:
        body = f["body"]
        if not body or body == "None":
            continue
        keys = list(dict.fromkeys(re.findall(r'(?:^|&)([A-Za-z_][\w]{0,12})=', body)))
        if len(keys) >= 4:
            conts = "; ".join(f'content:"{_sc(k)}="; nocase' for k in keys[:6])
            rules.append(f'alert tcp any any -> any any (msg:"[AUTO][S2] POST body param-set fingerprint"; '
                         f'flow:to_server,established; content:"POST"; depth:4; {conts}; '
                         f'sid:{sid}; rev:1;)'); sid += 1
            break

    # (d) 공격클래스 (URI/쿼리/바디, 케이스당 1)
    for f in mal:
        blob = f["path"] + "?" + f["query"] + " " + (f["body"] if f["body"] != "None" else "")
        hit = next(((nm, pat) for nm, pat, det in _ATTACK if det(blob)), None)
        if hit:
            rules.append(f'drop tcp any any -> any any (msg:"[AUTO][S2] {hit[0]}"; '
                         f'flow:to_server,established; pcre:"/{hit[1]}/"; sid:{sid}; rev:1;)'); sid += 1
            break

    return rules


def validate(path):
    """suricata -T 로 룰 문법 검증. (없으면 None, 실패 False, 통과 True)"""
    cfg = "/etc/suricata/suricata.yaml"
    cmd = ["suricata", "-T", "-S", path, "-l", "/tmp"]
    if os.path.exists(cfg):
        cmd[1:1] = ["-c", cfg]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        return (r.returncode == 0), (r.stderr or r.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return None, str(e)


def main():
    if len(sys.argv) < 2:
        raise SystemExit("사용법: python3 scripts/make_policy.py <name> [--validate]")
    name = sys.argv[1]
    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(ROOT, "reports", f"{name}.json"), encoding="utf-8") as f:
        report = json.load(f)
    rules, skipped = make_rules(report)                        # ── SECTION 1 (drop: IP/도메인/격리)

    # ── SECTION 2 (content) : evidence 의 경로/UA/바디에서 IP무관 지문 생성 ──
    s2 = []
    ev_path = os.path.join(ROOT, "output", name, "evidence.json")
    if os.path.exists(ev_path):
        with open(ev_path, encoding="utf-8") as f:
            evidence = json.load(f)
        iocs = (report.get("analysis") or {}).get("iocs", {})
        b_ips = {ip for k in ("c2", "delivery", "exfil") for ip in iocs.get(k, [])}
        s2 = content_rules(evidence, block_ips=b_ips, block_doms=set(iocs.get("domains", [])))

    out = os.path.join(ROOT, "reports", f"{name}.rules")
    header = [f"# auto-generated Suricata policy for {name}",
              f"# {len(rules)} block(S1) + {len(s2)} detect(S2) rules — 사람 검토 후 적용",
              "# S1=drop(초동 봉쇄, IP 로테이션 전까지) · S2=content(IP무관 지속 탐지, 기본 alert)",
              "# HOME_NET 은 suricata.yaml 에 정의되어 있어야 함"]
    body = header + ["", "# ═══ SECTION 1 · 초동 차단 (drop: IP/도메인/호스트격리) ═══"] + rules
    if s2:
        body += ["", "# ═══ SECTION 2 · 지속 탐지 (content, IP무관 · 기본 alert / 고신뢰만 drop) ═══"] + s2
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(body) + "\n")
    print(f"[policy] {out}  (S1={len(rules)}, S2={len(s2)})")
    if skipped:
        print(f"[policy] 건너뜀 {len(skipped)}건: {skipped[:8]}")
    if "--validate" in sys.argv:
        ok, msg = validate(out)
        tag = "PASS" if ok else ("SKIP(suricata 없음)" if ok is None else "FAIL")
        print(f"[validate] {tag}")
        if ok is False:
            print(msg[-800:])


if __name__ == "__main__":
    main()
