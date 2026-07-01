"""
Tier2 drill-down tools (FR-A).

Used when the Tier1 evidence is not enough and raw logs must be inspected.
When the model emits tool_calls, the orchestrator runs these and returns the result.

Common requirements:
  FR-C1: read raw logs (output/<name>/{zeek,suricata}). The "current pcap" is
         bound by the orchestrator via set_context() (model args are query-only).
  FR-C2: return compact/structured data, capped at RESULT_CAP.
  FR-C3: path-safe (never leave output/<name>); return {"error":...} instead of raising.
  FR-C4: deterministic. Type hints + docstrings -> auto schema. Registered in TOOLS.
"""
import json
import os

# ── current pcap context (set by the orchestrator; not exposed to the model) ──
_CTX = {"base": None}     # absolute path of output/<name>
_CACHE = {}               # abs path -> list[dict] (avoid re-reading the same log)

RESULT_CAP = 50           # max items per tool result (FR-C2)


def set_context(base: str) -> None:
    """Bind the output dir (output/<name>) of the pcap under analysis. Not model-facing."""
    _CTX["base"] = os.path.abspath(base)
    _CACHE.clear()


# ---------------------------------------------------------------------------
# internal helpers
# ---------------------------------------------------------------------------
def _read(rel_path):
    """Safely load a zeek/suricata NDJSON file -> list[dict]. None if unset/escaping."""
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


def _wrap(items, hint="narrow the query"):
    """Cap a list result at RESULT_CAP and attach count/truncated signals (FR-C2)."""
    return {"count": len(items),
            "truncated": max(0, len(items) - RESULT_CAP),
            "hint": hint if len(items) > RESULT_CAP else None,
            "results": items[:RESULT_CAP]}


def _no_ctx():
    return _CTX["base"] is None


# ── field projections (for compact returns) ──
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
# drill-down tools (model-facing)
# ---------------------------------------------------------------------------
def get_flow_detail(community_id: str) -> dict:
    """Return one flow's raw conn/http/dns/ssl/files records plus its Suricata
    alerts, joined by uid and community_id.

    Args:
        community_id: the flow identifier found in evidence alerts/files/external.
    """
    if _no_ctx():
        return {"error": "pcap context not set"}
    conn = _read("zeek/conn.log") or []
    uids = [c.get("uid") for c in conn
            if c.get("community_id") == community_id and c.get("uid")]
    if not uids:
        return {"error": f"no flow for community_id: {community_id}"}

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
    """Search raw Suricata alerts by signature substring / source IP / dest IP.
    Empty-string filters are ignored.

    Args:
        signature_contains: signature substring (e.g. 'Cobalt Strike').
        src: exact source IP.
        dst: exact destination IP.
    """
    if _no_ctx():
        return {"error": "pcap context not set"}
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
    """Search raw HTTP requests by host / URI substring. Empty-string filters are ignored.

    Args:
        host: HTTP Host substring (e.g. 'example.com').
        uri_contains: request URI substring (e.g. '/gate.php').
    """
    if _no_ctx():
        return {"error": "pcap context not set"}
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
    """Search raw DNS queries by domain substring.

    Args:
        query_contains: query-domain substring.
    """
    if _no_ctx():
        return {"error": "pcap context not set"}
    q = query_contains.lower()
    out = [_p_dns(d) for d in _read("zeek/dns.log") or []
           if not q or q in (d.get("query") or "").lower()]
    return _wrap(out)


def get_connections_by_ip(ip: str) -> dict:
    """Return every flow in which the IP is either source or destination.

    Args:
        ip: IP address to look up (internal or external).
    """
    if _no_ctx():
        return {"error": "pcap context not set"}
    out = [_p_conn(c) for c in _read("zeek/conn.log") or []
           if c.get("id.orig_h") == ip or c.get("id.resp_h") == ip]
    return _wrap(out)


def get_host_info(ip: str = "", mac: str = "") -> dict:
    """Resolve a host's identity (hostname/username/domain/mac) from raw
    kerberos/ntlm/dhcp/conn logs. Provide either ip or mac.

    Args:
        ip: internal host IP to look up.
        mac: MAC address to look up (when the IP is unknown).
    """
    if _no_ctx():
        return {"error": "pcap context not set"}
    if not ip and not mac:
        return {"error": "need either ip or mac"}

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
    """Return file metadata and the carved file's on-disk path (extract_files/) for a sha256.

    Args:
        sha256: SHA256 of the file (from evidence.files).
    """
    if _no_ctx():
        return {"error": "pcap context not set"}
    rec = next((f for f in _read("zeek/files.log") or [] if f.get("sha256") == sha256), None)
    if not rec:
        return {"error": f"no file with sha256: {sha256}"}
    info = _p_files(rec)
    extracted = rec.get("extracted")
    if extracted:
        p = os.path.join(_CTX["base"], "zeek", "extract_files", extracted)
        info["extracted_name"] = extracted
        info["disk_path"] = p if os.path.isfile(p) else None
    return info


# ---------------------------------------------------------------------------
# registry (FR-C4)
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
