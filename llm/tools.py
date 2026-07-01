"""
Tier2 드릴다운 tool (FR-A).

evidence(Tier1)로 부족할 때 raw 로그를 파고든다. 모델이 tool_calls 로 호출하면
오케스트레이터가 실행해서 결과를 되돌린다.

공통 요구사항:
  FR-C1: raw 로그(output/<name>/{zeek,suricata})를 읽음. "현재 pcap"은
         set_context() 로 오케스트레이터가 바인딩 (모델 인자는 query만).
  FR-C2: 반환은 compact/구조화 + 결과 크기 캡(RESULT_CAP).
  FR-C3: 경로 안전(output/<name> 밖 금지), 에러는 예외 말고 {"error":...}.
  FR-C4: 결정론적. 타입힌트+docstring → 자동 스키마. TOOLS 에 등록.
"""
import json
import os

# ── 현재 pcap 컨텍스트 (오케스트레이터가 세팅; 모델엔 노출 안 함) ──
_CTX = {"base": None}     # output/<name> 절대경로
_CACHE = {}               # 절대경로 -> list[dict] (같은 로그 반복 읽기 방지)

RESULT_CAP = 50           # tool 결과 최대 항목 수 (FR-C2)


def set_context(base: str) -> None:
    """분석 대상 pcap 의 output 디렉(output/<name>)을 바인딩. (모델 비노출)"""
    _CTX["base"] = os.path.abspath(base)
    _CACHE.clear()


# ---------------------------------------------------------------------------
# 내부 헬퍼
# ---------------------------------------------------------------------------
def _read(rel_path):
    """zeek/suricata NDJSON 안전 로딩 → list[dict]. 경로 이탈/미설정 시 None."""
    base = _CTX["base"]
    if base is None:
        return None
    path = os.path.realpath(os.path.join(base, rel_path))
    if not path.startswith(os.path.realpath(base) + os.sep):     # FR-C3
        return None
    if path in _CACHE:
        return _CACHE[path]
    out = []
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    _CACHE[path] = out
    return out


def _wrap(items, hint="조건을 좁히세요"):
    """리스트 결과를 RESULT_CAP 로 자르고 count/truncated 신호 부착. (FR-C2)"""
    return {"count": len(items),
            "truncated": max(0, len(items) - RESULT_CAP),
            "hint": hint if len(items) > RESULT_CAP else None,
            "results": items[:RESULT_CAP]}


def _no_ctx():
    return _CTX["base"] is None


# ── 필드 투영 (compact 반환용) ──
def _p_conn(c):
    return {k: c.get(k) for k in ("ts", "uid", "community_id", "id.orig_h", "id.orig_p",
                                  "id.resp_h", "id.resp_p", "proto", "service", "duration",
                                  "orig_bytes", "resp_bytes", "conn_state")}


def _p_alert(d):
    a = d.get("alert", {})
    return {"ts": d.get("timestamp"), "community_id": d.get("community_id"),
            "src": d.get("src_ip"), "sport": d.get("src_port"),
            "dst": d.get("dest_ip"), "dport": d.get("dest_port"), "proto": d.get("proto"),
            "signature": a.get("signature"), "category": a.get("category"),
            "severity": a.get("severity"), "sid": a.get("signature_id")}


def _p_http(d):
    return {k: d.get(k) for k in ("ts", "uid", "method", "host", "uri",
                                  "status_code", "resp_mime_types")}


def _p_dns(d):
    return {k: d.get(k) for k in ("ts", "uid", "query", "qtype_name", "rcode_name", "answers")}


def _p_ssl(d):
    return {k: d.get(k) for k in ("ts", "uid", "server_name", "version", "cipher",
                                  "established", "validation_status")}


def _p_files(d):
    return {k: d.get(k) for k in ("ts", "uid", "fuid", "source", "mime_type",
                                  "md5", "sha256", "seen_bytes", "extracted")}


# ---------------------------------------------------------------------------
# 드릴다운 tool (모델 호출용)
# ---------------------------------------------------------------------------
def get_flow_detail(community_id: str) -> dict:
    """community_id 로 한 flow 의 conn/http/dns/ssl/files 원본과 suricata alert 를
    uid·community_id 로 병합해 반환.

    Args:
        community_id: evidence 의 alert/files/external 에 있는 flow 식별자.
    """
    if _no_ctx():
        return {"error": "pcap 컨텍스트 미설정"}
    conn = _read("zeek/conn.log") or []
    uids = [c.get("uid") for c in conn
            if c.get("community_id") == community_id and c.get("uid")]
    if not uids:
        return {"error": f"해당 community_id 의 flow 없음: {community_id}"}

    dns = _read("zeek/dns.log") or []
    http = _read("zeek/http.log") or []
    ssl = _read("zeek/ssl.log") or []
    files = _read("zeek/files.log") or []

    flows = []
    for uid in uids:
        c = next((x for x in conn if x.get("uid") == uid), {})
        z = {}
        for name, recs, proj in (("dns", dns, _p_dns), ("http", http, _p_http),
                                 ("ssl", ssl, _p_ssl), ("files", files, _p_files)):
            hit = [proj(r) for r in recs if r.get("uid") == uid]
            if hit:
                z[name] = hit
        flows.append({"uid": uid, "conn": _p_conn(c), "zeek": z})

    eve = _read("suricata/eve.json") or []
    alerts = [_p_alert(d) for d in eve
              if d.get("event_type") == "alert" and d.get("community_id") == community_id]
    return {"community_id": community_id, "flows": flows,
            "alert_count": len(alerts), "alerts": alerts[:RESULT_CAP]}


def search_alerts(signature_contains: str = "", src: str = "", dst: str = "") -> dict:
    """suricata alert 원본을 시그니처/출발IP/도착IP 로 검색. 빈 문자열 조건은 무시.

    Args:
        signature_contains: 시그니처 부분일치 키워드 (예: 'Cobalt Strike').
        src: 출발 IP 정확일치.
        dst: 도착 IP 정확일치.
    """
    if _no_ctx():
        return {"error": "pcap 컨텍스트 미설정"}
    sig = signature_contains.lower()
    out = []
    for d in _read("suricata/eve.json") or []:
        if d.get("event_type") != "alert":
            continue
        a = d.get("alert", {})
        if sig and sig not in (a.get("signature") or "").lower():
            continue
        if src and d.get("src_ip") != src:
            continue
        if dst and d.get("dest_ip") != dst:
            continue
        out.append(_p_alert(d))
    return _wrap(out)


def search_http(host: str = "", uri_contains: str = "") -> dict:
    """HTTP 요청 원본을 host/URI 부분일치로 검색. 빈 문자열 조건은 무시.

    Args:
        host: HTTP Host 부분일치 (예: 'example.com').
        uri_contains: 요청 URI 부분일치 (예: '/gate.php').
    """
    if _no_ctx():
        return {"error": "pcap 컨텍스트 미설정"}
    h, u = host.lower(), uri_contains.lower()
    out = []
    for d in _read("zeek/http.log") or []:
        if h and h not in (d.get("host") or "").lower():
            continue
        if u and u not in (d.get("uri") or "").lower():
            continue
        out.append(_p_http(d))
    return _wrap(out)


def search_dns(query_contains: str = "") -> dict:
    """DNS 질의 원본을 도메인 부분일치로 검색.

    Args:
        query_contains: 질의 도메인 부분일치 키워드.
    """
    if _no_ctx():
        return {"error": "pcap 컨텍스트 미설정"}
    q = query_contains.lower()
    out = [_p_dns(d) for d in _read("zeek/dns.log") or []
           if not q or q in (d.get("query") or "").lower()]
    return _wrap(out)


def get_connections_by_ip(ip: str) -> dict:
    """특정 IP 가 출발이든 도착이든 관여한 모든 flow 를 반환.

    Args:
        ip: 조회할 IP 주소 (내부/외부 무관).
    """
    if _no_ctx():
        return {"error": "pcap 컨텍스트 미설정"}
    out = [_p_conn(c) for c in _read("zeek/conn.log") or []
           if c.get("id.orig_h") == ip or c.get("id.resp_h") == ip]
    return _wrap(out)


def get_host_info(ip: str = "", mac: str = "") -> dict:
    """IP 또는 MAC 으로 호스트 신원(hostname/username/domain/mac)을
    kerberos/ntlm/dhcp/conn 원본에서 확정 조회. ip/mac 중 하나는 필요.

    Args:
        ip: 조회할 내부 호스트 IP.
        mac: 조회할 MAC 주소 (ip 모를 때).
    """
    if _no_ctx():
        return {"error": "pcap 컨텍스트 미설정"}
    if not ip and not mac:
        return {"error": "ip 또는 mac 중 하나는 필요"}

    conn = _read("zeek/conn.log") or []
    info = {"ip": ip or None, "mac": mac or None,
            "hostname": None, "username": None, "ad_domain": None}

    for c in conn:
        if ip and c.get("id.orig_h") == ip and c.get("orig_l2_addr"):
            info["mac"] = info["mac"] or c["orig_l2_addr"]
        if ip and c.get("id.resp_h") == ip and c.get("resp_l2_addr"):
            info["mac"] = info["mac"] or c["resp_l2_addr"]

    uids = {c.get("uid") for c in conn
            if c.get("id.orig_h") == ip or c.get("id.resp_h") == ip}

    for d in _read("zeek/dhcp.log") or []:
        if (ip and (d.get("assigned_addr") == ip or d.get("client_addr") == ip)) \
           or (mac and d.get("mac") == mac):
            info["hostname"] = info["hostname"] or d.get("host_name")
            info["mac"] = info["mac"] or d.get("mac")
            info["ad_domain"] = info["ad_domain"] or d.get("domain")

    for d in _read("zeek/kerberos.log") or []:
        if d.get("uid") in uids and d.get("client") and "/" in d["client"]:
            user, _, realm = d["client"].partition("/")
            if not user.endswith("$"):
                info["username"] = info["username"] or user
            info["ad_domain"] = info["ad_domain"] or realm

    for d in _read("zeek/ntlm.log") or []:
        if d.get("uid") in uids and d.get("hostname"):
            info["hostname"] = info["hostname"] or d.get("hostname")

    return info


def get_malware_file(sha256: str) -> dict:
    """sha256 으로 파일 메타데이터 + carved 파일 디스크 경로(extract_files/)를 반환.

    Args:
        sha256: evidence.files 에 있는 파일 SHA256.
    """
    if _no_ctx():
        return {"error": "pcap 컨텍스트 미설정"}
    rec = next((f for f in _read("zeek/files.log") or [] if f.get("sha256") == sha256), None)
    if not rec:
        return {"error": f"해당 sha256 파일 없음: {sha256}"}
    info = _p_files(rec)
    extracted = rec.get("extracted")
    if extracted:
        p = os.path.join(_CTX["base"], "zeek", "extract_files", extracted)
        info["extracted_name"] = extracted
        info["disk_path"] = p if os.path.isfile(p) else None
    return info


# ---------------------------------------------------------------------------
# 등록소 (FR-C4)
# ---------------------------------------------------------------------------
TOOLS = [
    get_flow_detail,
    search_alerts,
    search_http,
    search_dns,
    get_connections_by_ip,
    get_host_info,
    get_malware_file,
]
AVAILABLE = {fn.__name__: fn for fn in TOOLS}
