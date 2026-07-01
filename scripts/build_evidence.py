#!/usr/bin/env python3
"""
evidence 빌더 (파이프라인 3단계: 정규화 및 압축)

  python3 build_evidence.py <name>
    입력:  output/<name>/{zeek/*.log, suricata/eve.json}
    출력:  output/<name>/evidence.json  (Tier1 요약, 결정론적)

설계 원칙(대화에서 확정):
  - Tier1 = 100% static/결정론적. 판단(휴리스틱) 없음. 판단은 LLM이 함.
  - 조인: zeek는 uid, zeek↔suricata는 community_id.
  - 포함/제외는 로그 필드 boolean 으로만 결정 (하드 시그널 유무).
  - alerts 는 severity 우선(1=최고위험), 전 시그니처 유지 (양으로 안 자름).
  - files 는 source=SSL(OCSP/인증서 부산물) 제외.
  - external(ip/도메인/sni)에 first_ts 부착 → 타임라인/patient-zero 재료.
  - 측면이동은 정황 요약만, 상세는 Tier2 드릴다운.
  - 캡 초과분은 조용히 버리지 않고 _truncation 에 기록.
"""
import json
import os
import sys
from collections import Counter, defaultdict

# ── 캡 (초과 시 _truncation 기록). 현재 pcap 규모선 거의 안 밟힘 ──
CAP_EXTERNAL_DOMAINS = 500
CAP_EXTERNAL_IPS = 500
CAP_EXTERNAL_SNI = 300
CAP_ALERT_SAMPLE_CIDS = 3    # alert 시그니처별 드릴다운용 community_id 표본 수

LM_LOGS = ["smb_files.log", "smb_mapping.log", "dce_rpc.log",
           "ldap_search.log", "ldap.log", "kerberos.log", "ntlm.log"]


# ---------------------------------------------------------------------------
def read_ndjson(path):
    """NDJSON(.log/eve.json) → list[dict]. 없으면 []."""
    out = []
    if not os.path.isfile(path):
        return out
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def is_real_host(ip):
    """멀티캐스트/브로드캐스트/link-local/미지정 제외 (진짜 내부 호스트만)."""
    if not ip or ip in ("0.0.0.0", "255.255.255.255"):
        return False
    if ":" in ip:                       # IPv6 (link-local 등)은 일단 제외
        return False
    if ip.startswith("169.254.") or ip.endswith(".255"):
        return False
    try:
        o1 = int(ip.split(".")[0])
    except ValueError:
        return False
    if 224 <= o1 <= 239:                # multicast
        return False
    return True


# ---------------------------------------------------------------------------
def build_evidence(name, root="/home/qkekdhd/auto_packet_analyze_v3"):
    base = os.path.join(root, "output", name)
    Z = os.path.join(base, "zeek")
    S = os.path.join(base, "suricata")
    if not os.path.isdir(base):
        raise SystemExit(f"출력 폴더 없음: {base} (extract_log.sh 먼저 실행)")

    trunc = {}

    # ── conn.log: flow 인덱스 (uid 허브) ──
    conn = read_ndjson(f"{Z}/conn.log")
    flow = {}                    # uid -> conn record
    cid_of = {}                  # uid -> community_id
    for d in conn:
        uid = d.get("uid")
        if uid:
            flow[uid] = d
            cid_of[uid] = d.get("community_id")

    # ── suricata eve.json: alert 그룹 (community_id 조인) ──
    eve = read_ndjson(f"{S}/eve.json")
    alert_cids = set()
    sig_stat = {}                # (sig,cat,sev) -> dict(count, first_ts, src, dst, cids)
    for d in eve:
        if d.get("event_type") != "alert":
            continue
        cid = d.get("community_id")
        alert_cids.add(cid)
        a = d.get("alert", {})
        key = (a.get("signature"), a.get("category"), a.get("severity"))
        st = sig_stat.setdefault(key, {"count": 0, "first_ts": None,
                                       "src": set(), "dst": set(), "cids": []})
        st["count"] += 1
        ts = d.get("timestamp")
        if ts and (st["first_ts"] is None or ts < st["first_ts"]):
            st["first_ts"] = ts
        if d.get("src_ip"):
            st["src"].add(d["src_ip"])
        if d.get("dest_ip"):
            st["dst"].add(d["dest_ip"])
        if cid and len(st["cids"]) < CAP_ALERT_SAMPLE_CIDS and cid not in st["cids"]:
            st["cids"].append(cid)

    # ── files.log: source=SSL(OCSP/cert) 제외 + sha256 로 dedup ──
    #   같은 파일이 여러 flow/청크로 여러 번 찍힘 → 해시로 묶어 1개(count+first_ts).
    files_raw = read_ndjson(f"{Z}/files.log")
    file_uids = set()
    files_by_key = {}
    dropped_ssl = 0
    for f in files_raw:
        if f.get("uid"):
            file_uids.add(f["uid"])
        if f.get("source") == "SSL":     # OCSP/인증서 부산물 → 멀웨어 IOC 아님
            dropped_ssl += 1
            continue
        key = f.get("sha256") or f.get("fuid") or f.get("uid")   # 해시 없으면 fuid/uid
        ts = f.get("ts")
        rec = files_by_key.setdefault(key, {
            "sha256": f.get("sha256"), "md5": f.get("md5"),
            "mime": f.get("mime_type"), "bytes": f.get("seen_bytes"),
            "first_ts": None, "count": 0,
            "sources": set(), "community_ids": [],
        })
        rec["count"] += 1
        if f.get("source"):
            rec["sources"].add(f["source"])
        if ts and (rec["first_ts"] is None or ts < rec["first_ts"]):
            rec["first_ts"] = ts
        cid = cid_of.get(f.get("uid"))
        if cid and cid not in rec["community_ids"] and len(rec["community_ids"]) < CAP_ALERT_SAMPLE_CIDS:
            rec["community_ids"].append(cid)
    files = [{**r, "sources": sorted(r["sources"])}
             for r in sorted(files_by_key.values(),
                             key=lambda x: (x["first_ts"] is None, x["first_ts"]))]
    if dropped_ssl:
        trunc["files_ssl_excluded"] = dropped_ssl

    # ── 측면이동 로그: uid 집합 + 정황 요약 ──
    lm_uids = set()
    lm_records = {}
    for lg in LM_LOGS:
        recs = read_ndjson(f"{Z}/{lg}")
        lm_records[lg] = recs
        for r in recs:
            if r.get("uid"):
                lm_uids.add(r["uid"])

    def internal_pairs(recs, limit=10):
        pairs = Counter()
        for r in recs:
            s, d = r.get("id.orig_h"), r.get("id.resp_h")
            if s and d:
                pairs[(s, d)] += 1
        return [[s, d] for (s, d), _ in pairs.most_common(limit)]

    def top_field(recs, field, limit=8):
        c = Counter(r.get(field) for r in recs if r.get(field))
        return [k for k, _ in c.most_common(limit)]

    smb_recs = lm_records["smb_files.log"] + lm_records["smb_mapping.log"]
    lateral_movement = {
        "smb": {"events": len(smb_recs),
                "internal_pairs": internal_pairs(smb_recs),
                "shares": top_field(lm_records["smb_mapping.log"], "share_type")},
        "dcerpc": {"events": len(lm_records["dce_rpc.log"]),
                   "top_endpoints": top_field(lm_records["dce_rpc.log"], "endpoint")},
        "ldap": {"searches": len(lm_records["ldap_search.log"])},
        "kerberos": {"events": len(lm_records["kerberos.log"])},
    }

    # ── 하드 시그널 분할 (전부 boolean) ──
    hard, noise = 0, 0
    for uid, d in flow.items():
        cid = cid_of.get(uid)
        if (cid in alert_cids) or (uid in file_uids) or (uid in lm_uids) \
           or (d.get("local_resp") is False):
            hard += 1
        else:
            noise += 1

    # ── hosts 인벤토리 (목표1) ──
    hosts = {}

    def host_slot(ip):
        return hosts.setdefault(ip, {"ip": ip, "mac": None, "hostname": None,
                                     "username": None, "ad_domain": None,
                                     "scope": "internal",
                                     "first_ts": None, "last_ts": None})

    for d in conn:
        ts = d.get("ts")
        for ipk, mack, localk in [("id.orig_h", "orig_l2_addr", "local_orig"),
                                  ("id.resp_h", "resp_l2_addr", "local_resp")]:
            ip = d.get(ipk)
            if not (d.get(localk) and is_real_host(ip)):
                continue
            h = host_slot(ip)
            if d.get(mack):
                h["mac"] = h["mac"] or d[mack]
            if ts:
                h["first_ts"] = ts if h["first_ts"] is None else min(h["first_ts"], ts)
                h["last_ts"] = ts if h["last_ts"] is None else max(h["last_ts"], ts)

    # dhcp → hostname/mac
    for d in read_ndjson(f"{Z}/dhcp.log"):
        ip = d.get("assigned_addr") or d.get("client_addr")
        if ip in hosts:
            hosts[ip]["hostname"] = hosts[ip]["hostname"] or d.get("host_name")
            if d.get("mac"):
                hosts[ip]["mac"] = hosts[ip]["mac"] or d["mac"]

    # kerberos client → username + ad_domain (machine account($) 제외)
    for d in read_ndjson(f"{Z}/kerberos.log"):
        client = d.get("client")
        fl = flow.get(d.get("uid"), {})
        ip = fl.get("id.orig_h")
        if not (client and ip in hosts and "/" in client):
            continue
        user, _, realm = client.partition("/")
        if user.endswith("$"):           # 컴퓨터 계정 → username 아님
            hosts[ip]["ad_domain"] = hosts[ip]["ad_domain"] or realm
            continue
        hosts[ip]["username"] = hosts[ip]["username"] or user
        hosts[ip]["ad_domain"] = hosts[ip]["ad_domain"] or realm

    # ntlm → hostname 보강
    for d in read_ndjson(f"{Z}/ntlm.log"):
        fl = flow.get(d.get("uid"), {})
        ip = fl.get("id.orig_h")
        if ip in hosts and d.get("hostname"):
            hosts[ip]["hostname"] = hosts[ip]["hostname"] or d["hostname"]

    # ── external (목표2/4/5): ip/도메인/sni + first_ts ──
    ext_ip = {}          # ip -> {first_ts, conns}
    for d in conn:
        if d.get("local_resp") is False:
            ip = d.get("id.resp_h"); ts = d.get("ts")
            e = ext_ip.setdefault(ip, {"ip": ip, "first_ts": None, "conns": 0})
            e["conns"] += 1
            if ts and (e["first_ts"] is None or ts < e["first_ts"]):
                e["first_ts"] = ts

    ext_dom = {}         # query -> {first_ts, answers}
    for d in read_ndjson(f"{Z}/dns.log"):
        q = d.get("query"); ts = d.get("ts")
        if not q or q.endswith(".arpa") or q.endswith(".local"):
            continue
        e = ext_dom.setdefault(q, {"query": q, "first_ts": None, "answers": None})
        if ts and (e["first_ts"] is None or ts < e["first_ts"]):
            e["first_ts"] = ts
            e["answers"] = d.get("answers")

    ext_sni = {}         # sni -> {first_ts}
    for d in read_ndjson(f"{Z}/ssl.log"):
        sni = d.get("server_name"); ts = d.get("ts")
        if not sni:
            continue
        e = ext_sni.setdefault(sni, {"sni": sni, "first_ts": None})
        if ts and (e["first_ts"] is None or ts < e["first_ts"]):
            e["first_ts"] = ts

    # 시간순 정렬 + 캡 (초과분은 _truncation)
    def capped(d, cap, label):
        items = sorted(d.values(), key=lambda x: (x["first_ts"] is None, x["first_ts"]))
        if len(items) > cap:
            trunc[label] = len(items) - cap
            items = items[:cap]
        return items

    external = {
        "ips": capped(ext_ip, CAP_EXTERNAL_IPS, "external_ips_dropped"),
        "domains": capped(ext_dom, CAP_EXTERNAL_DOMAINS, "external_domains_dropped"),
        "sni": capped(ext_sni, CAP_EXTERNAL_SNI, "external_sni_dropped"),
    }

    # ── alerts: severity 우선(1 먼저), 동률이면 count 많은 순 ──
    def sev_key(item):
        (sig, cat, sev), st = item
        return (sev if sev is not None else 99, -st["count"])

    alerts = []
    for (sig, cat, sev), st in sorted(sig_stat.items(), key=sev_key):
        alerts.append({
            "signature": sig, "category": cat, "severity": sev,
            "count": st["count"], "first_ts": st["first_ts"],
            "src_ips": sorted(st["src"]), "dst_ips": sorted(st["dst"]),
            "sample_community_ids": st["cids"],
        })

    # ── meta / 조립 ──
    conn_ts = [d.get("ts") for d in conn if d.get("ts")]
    cap_start = min(conn_ts) if conn_ts else None
    cap_end = max(conn_ts) if conn_ts else None

    evidence = {
        "meta": {
            "pcap": name,
            "capture_start": cap_start,
            "capture_end": cap_end,
            "duration_s": round(cap_end - cap_start, 1) if conn_ts else None,
            "counts": {"total_flows": len(flow), "hard_signal": hard, "noise": noise},
        },
        "hosts": list(hosts.values()),
        "alerts": alerts,
        "files": files,
        "external": external,
        "lateral_movement": lateral_movement,
        "_truncation": trunc,
    }
    return evidence


# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        raise SystemExit("사용법: python3 build_evidence.py <name>")
    name = sys.argv[1]
    # scripts/ 안에 있으므로 부모 디렉터리가 프로젝트 루트
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ev = build_evidence(name, root)
    out = os.path.join(root, "output", name, "evidence.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(ev, f, ensure_ascii=False, indent=2)
    size = os.path.getsize(out) / 1024
    print(f"[evidence] {out}  ({size:.1f} KB)")
    print(f"  hosts={len(ev['hosts'])} alerts={len(ev['alerts'])} "
          f"files={len(ev['files'])} ext_ip={len(ev['external']['ips'])} "
          f"ext_dom={len(ev['external']['domains'])} sni={len(ev['external']['sni'])}")
    if ev["_truncation"]:
        print(f"  _truncation={ev['_truncation']}")


if __name__ == "__main__":
    main()
