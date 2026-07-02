"""
IOC 검증 게이트 (결정론적 후처리).

LLM 보고서에 나온 IP/도메인/해시를 evidence 의 실제 관측값과 대조해서
- 오염된(문자 섞인) IP        → corrupted
- evidence 에 없는 값         → ungrounded (환각 or 오타)
를 잡아낸다. 차단 정책에 오염 IOC 가 흘러드는 걸 막는 마지막 관문.

원칙: LLM 이 재타이핑한 값은 믿지 않는다. 근거는 evidence 가 소유한다.
"""
import re

# IP 후보: 첫/마지막 옥텟이 숫자인 4-마디 토큰 (정상 + 오염 둘 다 포착)
#   172.6gan.139.101 / 67.2inet.228.199 같은 오염도 잡히도록 중간 옥텟은 영숫자 허용
_IP_CAND = re.compile(r'\b\d{1,3}\.[0-9A-Za-z]{1,9}\.[0-9A-Za-z]{1,9}\.\d{1,3}\b')
_DOMAIN = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
_MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')

# 도메인 오탐 억제: 파일명/식별자 등 흔한 비-IOC 접미사
_DOMAIN_STOP = {"e.g", "i.e", "etc", "0.0", "microsoft.com", "example.com"}


def _valid_ip(tok):
    parts = tok.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not (0 <= int(p) <= 255):
            return False
    return True


def collect_evidence_iocs(evidence):
    """evidence.json 에서 '실제 관측된' IOC 집합을 모은다 (ground truth)."""
    ips, domains, hashes = set(), set(), set()

    ext = evidence.get("external", {})
    for x in ext.get("ips", []):
        if x.get("ip"):
            ips.add(x["ip"])
    for d in ext.get("domains", []):
        if d.get("query"):
            domains.add(d["query"].lower())
    for s in ext.get("sni", []):
        if s.get("sni"):
            domains.add(s["sni"].lower())

    for a in evidence.get("alerts", []):
        ips.update(a.get("src_ips") or [])
        ips.update(a.get("dst_ips") or [])

    for h in evidence.get("hosts", []):
        if h.get("ip"):
            ips.add(h["ip"])

    an = evidence.get("anomalies", {})
    for key in ("beacons", "exfil_candidates", "no_dns_direct", "odd_ports"):
        for e in an.get(key, []):
            if e.get("dst"):
                ips.add(e["dst"])

    files = evidence.get("files", {})
    cands = files.get("malware_candidates", []) if isinstance(files, dict) else files
    for f in cands or []:
        if f.get("sha256"):
            hashes.add(f["sha256"].lower())
        if f.get("md5"):
            hashes.add(f["md5"].lower())

    # username(예: tommy.vega)은 도메인 정규식에 걸리므로 도메인 검사에서 제외
    usernames = {h["username"].lower() for h in evidence.get("hosts", [])
                 if h.get("username")}

    ips.discard(None)
    return {"ips": ips, "domains": domains, "hashes": hashes,
            "usernames": usernames}


def check_iocs(report, evidence):
    """보고서 텍스트 × evidence → 문제 IOC 목록. 비어 있으면 통과."""
    truth = collect_evidence_iocs(evidence)
    findings = []
    seen = set()

    def add(kind, value, detail):
        k = (kind, value)
        if k not in seen:
            seen.add(k)
            findings.append({"kind": kind, "value": value, "detail": detail})

    # ── IP ──
    for tok in _IP_CAND.findall(report):
        if _valid_ip(tok):
            if tok not in truth["ips"]:
                add("ungrounded_ip", tok, "evidence 에 없는 IP (환각 또는 오타)")
        else:
            add("corrupted_ip", tok, "IP 형식 오염 (문자 섞임)")

    # ── 해시 ──
    for h in _SHA256.findall(report) + _MD5.findall(report):
        if h.lower() not in truth["hashes"]:
            add("ungrounded_hash", h, "evidence 에 없는 해시")

    # ── 도메인 (best-effort: 부분일치로 오탐 억제) ──
    for dom in _DOMAIN.findall(report):
        d = dom.lower()
        if d in _DOMAIN_STOP or d in truth["usernames"] or _valid_ip(dom):
            continue
        # evidence 의 어떤 도메인과도 서로 부분일치 안 하면 근거 없음
        if not any(d in gt or gt in d for gt in truth["domains"]):
            add("ungrounded_domain", dom, "evidence 에 없는 도메인")

    return findings


def format_findings(findings):
    if not findings:
        return "[ioc-gate] ✅ 모든 IOC 가 evidence 에 근거함 (통과)"
    lines = [f"[ioc-gate] ⚠️ {len(findings)}개 문제 IOC 발견:"]
    for f in findings:
        lines.append(f"  - [{f['kind']}] {f['value']}  ← {f['detail']}")
    return "\n".join(lines)
