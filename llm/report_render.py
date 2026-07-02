"""
보고서 렌더러 (결정론).

LLM(forensic)이 뱉은 구조화 JSON을 받아, IP/도메인/해시를 evidence.json 의 실제
관측값과 exact-match 검증한 뒤 고정 6-섹션 마크다운으로 찍는다.

핵심 원칙(대화에서 확정):
  - IOC 문자열은 LLM 이 아니라 evidence 가 소유한다. LLM 은 "어느 값이 공격이냐"를
    지목만 하고, 실제 문자열은 여기서 evidence 대조 후 렌더한다.
    → 17.16.1.66(오타)·104⇥⇥4.21.16.1(공백삽입) 같은 오염은 대조에서 탈락 → 차단정책에
      절대 안 들어감. LLM 텍스트를 그대로 안 믿는다.
  - 탈락시킨 값은 조용히 버리지 않고 "미검증" 목록에 남긴다(투명성).
  - victims 표의 mac/hostname/username/role 은 LLM 이 아니라 evidence 에서 채운다.

run.py 가 chat(format=REPORT_SCHEMA) 로 받은 dict 와 tools.evidence 를 넘겨 호출:
    md, rejected = render(report_json, evidence)
"""
import ipaddress
import re

# run.py 에서 forensic 2상 호출에 쓸 스키마 (여기 정의를 복사해 쓰거나 import).
REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "executive_summary": {"type": "string"},
        "victims": {"type": "array", "items": {
            "type": "object",
            "properties": {"ip": {"type": "string"},
                           "status": {"type": "string"},
                           "note": {"type": "string"}},
            "required": ["ip", "status"]}},
        "attacker_ips": {"type": "array", "items": {
            "type": "object",
            "properties": {"ip": {"type": "string"},
                           "role": {"type": "string"}},
            "required": ["ip", "role"]}},
        # domains 는 required (Ollama format 은 required 만 보장 → 키 생략 방지).
        # file_hashes 는 스키마에서 뺌: 해시는 LLM 선택이 아니라 evidence files[] 전수 나열
        # (get_files()["malware_candidates"]) 로 렌더러가 직접 채움 → 해시 블라인드 원천 차단.
        "domains": {"type": "array", "items": {"type": "string"}},
        "malware_behavior": {"type": "array", "items": {
            "type": "object",
            "properties": {"host": {"type": "string"},
                           "detail": {"type": "string"}},
            "required": ["host", "detail"]}},
        "timeline": {"type": "array", "items": {
            "type": "object",
            "properties": {"ts": {"type": "string"},
                           "event": {"type": "string"}},
            "required": ["ts", "event"]}},
        "anomaly_analysis": {"type": "array", "items": {"type": "string"}},
        "assessment": {"type": "string"},
    },
    # 서사 필드(malware_behavior/anomaly_analysis)는 optional — required 로 강제하면
    # 정보 없을 때 패딩 유발. 빈 값은 렌더러가 "None identified." 로 처리.
    "required": ["executive_summary", "victims", "attacker_ips", "domains",
                 "timeline", "assessment"],
}

_HEX = re.compile(r'^(?:[0-9a-f]{32}|[0-9a-f]{64})$')


def _norm_ip(s):
    """유효 IP면 정규화 문자열, 아니면 None.

    원문을 먼저 시도(IPv6 ff02::fb 보존) → 실패 시 숫자·점만 남겨 IPv4 잔해 정규화
    (10⇥⇥4.21.16.1 → 104.21.16.1 같은 공백삽입 오염 복원용).
    """
    try:
        return str(ipaddress.ip_address((s or "").strip()))
    except ValueError:
        pass
    cand = re.sub(r'[^\d.]', '', s or '')
    try:
        return str(ipaddress.ip_address(cand))
    except ValueError:
        return None


def allowed_iocs(evidence):
    """evidence.json 전체를 훑어 실제 관측된 IP/도메인/해시 허용집합 생성."""
    ips, domains, hashes = set(), set(), set()

    def walk(o):
        if isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
        elif isinstance(o, str):
            s = o.strip().lower()
            try:
                ipaddress.ip_address(s)
                ips.add(s)
                return
            except ValueError:
                pass
            if _HEX.match(s):
                hashes.add(s)
            elif re.fullmatch(r'(?:[a-z0-9_-]+\.)+[a-z]{2,}', s):
                domains.add(s)
    walk(evidence)
    return {"ips": ips, "domains": domains, "hashes": hashes}


def _host_index(evidence):
    return {h.get("ip"): h for h in evidence.get("hosts", []) if h.get("ip")}


def render(report, evidence, malware_candidates=None):
    """(markdown, rejected, warnings) 반환.

    - rejected : evidence 대조 탈락한 IOC (내용물이 틀림 → 정책 자동적용 하드블록용)
    - warnings : 검토 범위 불완전 등 (정책은 안전하나 사람이 알고 결정 → o/x 질문에 노출)
    - malware_candidates : tools.get_files()["malware_candidates"] (해시 전수 나열용).
      None 이면 evidence.files 를 그대로 쓰지 않고 빈 목록 취급(노이즈 유입 방지).
    """
    allow = allowed_iocs(evidence)
    hosts = _host_index(evidence)
    rejected, warnings = [], []

    def verify_ip(raw):
        """evidence 에 있는 IP면 정규화된 값 반환, 아니면 None(+rejected 기록)."""
        n = _norm_ip(raw)
        if n and n in allow["ips"]:
            return n
        rejected.append(("ip", raw))
        return None

    out = []

    # ── Executive Summary ──
    out.append("## Executive Summary")
    out.append((report.get("executive_summary") or "None identified.").strip())

    # ── 1. Victims (호스트 상세는 evidence 에서, status/note 는 LLM) ──
    out.append("\n## 1. Victims / Internal Hosts")
    out.append("| IP | MAC | Hostname | Username | Role | Status |")
    out.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
    for v in report.get("victims", []):
        ip = _norm_ip(v.get("ip")) or (v.get("ip") or "")
        h = hosts.get(ip)
        if not h:                       # evidence 에 없는 호스트 → 표에 안 넣고 기록
            rejected.append(("victim_ip", v.get("ip")))
            continue
        status = (v.get("status") or "unknown").strip()
        out.append(f"| {ip} | {h.get('mac') or 'unknown'} | "
                   f"{h.get('hostname') or 'unknown'} | {h.get('username') or 'unknown'} | "
                   f"{h.get('role') or 'unknown'} | {status} |")

    # ── 2. Attacker Endpoints & IOCs (전부 evidence 대조 후 렌더) ──
    out.append("\n## 2. Attacker Endpoints & IOCs")
    ip_lines, seen = [], set()
    for a in report.get("attacker_ips", []):
        n = verify_ip(a.get("ip"))
        if n and n not in seen:
            seen.add(n)
            ip_lines.append(f"    - {n} ({(a.get('role') or 'unknown').strip()})")
    out.append("- **External IPs:**")
    out.extend(ip_lines or ["    - None identified."])

    dom_lines, seend = [], set()
    for d in report.get("domains", []):
        dl = (d or "").strip().lower()
        ok = dl in allow["domains"] or any(dl.endswith("." + a) for a in allow["domains"])
        if not ok:
            rejected.append(("domain", d))
            continue
        if dl not in seend:
            seend.add(dl)
            dom_lines.append(f"    - {dl}")
    out.append("- **Domains:**")
    out.extend(dom_lines or ["    - None identified."])

    # 해시: LLM 선택과 무관하게 malware_candidates 전수 나열 (#6 해시 블라인드 차단).
    #   필터 정의는 tools.INTERESTING_MIME 한 곳에만 존재 → mime 드리프트 없음.
    hsh_lines, seenh = [], set()
    for f in (malware_candidates or []):
        h = (f.get("sha256") or "sha256 unknown")
        if h in seenh:
            continue
        seenh.add(h)
        hsh_lines.append(f"    - {h} — {f.get('bytes', '?')} bytes, {f.get('mime')}")
    out.append("- **File hashes:**")
    out.extend(hsh_lines or ["    - None in evidence."])

    # ── 3. Malware & Attack Behavior (서사 — LLM) ──
    out.append("\n## 3. Malware & Attack Behavior (per host)")
    mb = report.get("malware_behavior", [])
    out.extend([f"- **{(m.get('host') or '').strip()}**: {(m.get('detail') or '').strip()}"
                for m in mb] or ["None identified."])

    # ── 4. Infection Timeline (서사 — LLM) ──
    out.append("\n## 4. Infection Timeline")
    tl = report.get("timeline", [])
    out.extend([f"{i}. **{(t.get('ts') or '').strip()}**: {(t.get('event') or '').strip()}"
                for i, t in enumerate(tl, 1)] or ["None identified."])

    # ── 5. Anomaly Analysis (서사 — LLM) ──
    out.append("\n## 5. Anomaly Analysis")
    aa = report.get("anomaly_analysis", [])
    out.extend([f"- {s.strip()}" for s in aa] or ["None identified."])

    # ── 산문 필드 IP assertion — 구조화 필드가 못 덮는 유일한 구멍(17.16.1.66 재발 방지) ──
    #   산문의 IP는 렌더는 하되(cosmetic), evidence 에 없으면 rejected 로 정책 게이트에 태움.
    prose = " ".join(
        [report.get("executive_summary") or "", report.get("assessment") or ""]
        + [t.get("event") or "" for t in tl]
        + [m.get("detail") or "" for m in mb]
        + [s or "" for s in aa])
    prose_seen = set()
    for pm in re.finditer(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', prose):
        tok = pm.group()
        if tok not in allow["ips"] and tok not in prose_seen:
            prose_seen.add(tok)
            rejected.append(("prose_ip", tok))

    # ── anomaly 검토 커버리지 (경고만 — 그룹핑 서술이 정당하므로 하드블록 아님) ──
    #   지표(카운트)가 그룹핑을 오탐하므로 warnings 채널로만. 게이트급 승격은 anomaly에
    #   결정론 id 부여 + keys 참조 스키마로 커버리지를 정확히 잰 뒤에.
    n_anom = sum(len(v) for v in evidence.get("anomalies", {}).values()
                 if isinstance(v, list))
    if n_anom and len(aa) < n_anom:
        warnings.append(f"anomalies {n_anom}건 중 {len(aa)}줄만 서술 — "
                        f"그룹 서술일 수 있으나 미검토 항목 확인 권장")

    # ── 6. Assessment & Limitations (서사 — LLM) ──
    out.append("\n## 6. Assessment & Limitations")
    out.append((report.get("assessment") or "None identified.").strip())

    # ── 미검증 IOC (조용히 버리지 않음 — 내용 오염) ──
    if rejected:
        out.append("\n## ⚠️ Dropped (not found in evidence — possible LLM corruption)")
        for kind, val in rejected:
            out.append(f"- [{kind}] {val!r}")

    # ── 경고 (범위 불완전 — 정책은 안전, 사람 참고) ──
    if warnings:
        out.append("\n## ⚠️ Review notes (coverage — not a corruption)")
        for w in warnings:
            out.append(f"- {w}")

    return "\n".join(out), rejected, warnings
