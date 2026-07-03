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
  - Suricata 디코더 진단("SURICATA ..." / Generic Protocol Command Decode)은
    위협 alert 가 아니라 캡처 품질 신호 → capture_diagnostics 로 분리.
  - anomalies = 무시그니처 행동 측정치(비콘 주기, 업로드 비율, odd-port 등).
    수치만 계산해서 노출, 악성 판단은 LLM 몫. 하한/캡은 크기 제한용이며 _floors 에 명시.
"""
import json
import math
import os
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

# ── 캡 (초과 시 _truncation 기록). 현재 pcap 규모선 거의 안 밟힘 ──
CAP_EXTERNAL_DOMAINS = 500
CAP_EXTERNAL_IPS = 500
CAP_EXTERNAL_SNI = 300
CAP_ALERT_SAMPLE_CIDS = 3    # alert 시그니처별 드릴다운용 community_id 표본 수

# ── anomalies 보고 하한/캡 (판단 기준 아님 — 표본 부족·크기 제한용, _floors 로 노출) ──
ANOM_BEACON_MIN_CONNS = 5    # 이 미만이면 주기(지터) 계산 표본 부족
ANOM_FANOUT_MIN_DSTS = 5     # 내부 fan-out 보고 하한
ANOM_LIST_CAP = 15           # 각 목록 최대 길이
ANOM_ENTROPY_MIN = 3.5       # DGA 후보 보고 하한 (첫 라벨 셰넌 엔트로피)
WELL_KNOWN_PORTS = {21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587,
                    993, 995, 3478, 8080, 8443}
WS_ODD_EGRESS_PORTS = {25: "smtp", 465: "smtps", 587: "submission",
                       6667: "irc", 3389: "rdp"}    # 워크스테이션발이면 역할 이탈
LATERAL_PORTS = {135, 139, 445, 3389, 5985}         # 내부 fan-out 대상 포트

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


# ── 타임스탬프 통일: 내부 계산은 epoch 그대로, 최종 출력만 UTC ISO ──
#   zeek는 epoch float, suricata는 로컬오프셋 문자열(+0900)이라 형식이 섞임
#   → LLM이 타임라인 만들 때 혼동하므로 evidence.json 에서는 한 형식으로 통일.
_TS_KEYS = {"ts", "first_ts", "last_ts", "capture_start", "capture_end"}


def to_utc_iso(v):
    """epoch(float/int) 또는 오프셋 ISO 문자열 → 'YYYY-MM-DDTHH:MM:SS.mmmZ' (UTC)."""
    if v is None:
        return None
    try:
        if isinstance(v, (int, float)):
            dt = datetime.fromtimestamp(v, tz=timezone.utc)
        elif isinstance(v, str):
            s = v.strip().replace("Z", "+0000")
            fmt = "%Y-%m-%dT%H:%M:%S.%f%z" if "." in s else "%Y-%m-%dT%H:%M:%S%z"
            dt = datetime.strptime(s, fmt)
        else:
            return v
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except (ValueError, OverflowError, OSError):
        return v                      # 파싱 불가 값은 원본 유지 (조용히 버리지 않음)


def normalize_ts(obj):
    """evidence 트리 전체에서 _TS_KEYS 이름의 값만 UTC ISO 로 변환."""
    if isinstance(obj, dict):
        return {k: (to_utc_iso(v) if k in _TS_KEYS else normalize_ts(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [normalize_ts(x) for x in obj]
    return obj


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


def is_unicast_mac(mac):
    """브로드캐스트/멀티캐스트 MAC 제외. 없으면(None) 판단 보류 → True.

    IP 휴리스틱(.255)은 서브넷을 모르면 /25 브로드캐스트(x.x.x.127) 등을 못 잡음
    → MAC 이 확실한 신호 (whatthef 케이스에서 실증).
    """
    if not mac:
        return True
    m = mac.lower()
    return not (m == "ff:ff:ff:ff:ff:ff"
                or m.startswith("01:00:5e")     # IPv4 multicast
                or m.startswith("33:33"))       # IPv6 multicast


def is_capture_diagnostic(sig, cat):
    """Suricata 디코더 진단 이벤트 판별 (위협 alert 아님).

    'SURICATA IPv4 invalid checksum' 류는 캡처 호스트의 NIC checksum offloading
    아티팩트가 대부분 → alerts 에 섞이면 benign pcap 에서 가짜 사건을 유발.
    """
    return (sig or "").startswith("SURICATA ") \
        or cat == "Generic Protocol Command Decode"


def shannon_entropy(s):
    """문자열 셰넌 엔트로피 (DGA 후보 측정용)."""
    if not s:
        return 0.0
    n = len(s)
    return round(-sum(c / n * math.log2(c / n) for c in Counter(s).values()), 2)


def build_anomalies(conn, hosts, dns_recs):
    """무시그니처 행동 측정 (제로데이 대비 채널).

    원칙: 수치만 계산, 악성 판단 없음 — "얘가 왜 이런 행동을?"의 후보 목록.
    하한(_floors)은 표본 부족/크기 제한용이며 판단 기준이 아님.
    """
    ext = [d for d in conn if d.get("local_resp") is False and d.get("id.resp_h")]

    # 1) 비콘 주기성: 외부 (dst,port)별 연결 간격의 지터. 낮을수록 기계적 주기 접속.
    grp = defaultdict(list)      # (dst, port) -> [ts...]
    grp_bytes = defaultdict(int)
    for d in ext:
        key = (d["id.resp_h"], d.get("id.resp_p"))
        if d.get("ts"):
            grp[key].append(d["ts"])
        grp_bytes[key] += d.get("orig_bytes") or 0
    beacons = []
    for (dst, port), tss in grp.items():
        if len(tss) < ANOM_BEACON_MIN_CONNS:
            continue
        tss.sort()
        ivals = [b - a for a, b in zip(tss, tss[1:])]
        mean = statistics.mean(ivals)
        if mean <= 0:
            continue
        stdev = statistics.pstdev(ivals)
        beacons.append({"dst": dst, "port": port, "conns": len(tss),
                        "interval_avg_s": round(mean, 2),
                        "jitter_pct": round(stdev / mean * 100, 1),
                        "total_bytes_out": grp_bytes[(dst, port)]})
    beacons.sort(key=lambda x: x["jitter_pct"])         # 기계적인 것부터

    # 2) 업로드 비율: 외부 dst 별 송신/수신 바이트. 송신 압도 = 유출 후보.
    updown = defaultdict(lambda: {"out": 0, "in": 0, "flows": 0})
    for d in ext:
        u = updown[d["id.resp_h"]]
        u["out"] += d.get("orig_bytes") or 0
        u["in"] += d.get("resp_bytes") or 0
        u["flows"] += 1
    exfil = [{"dst": ip, "bytes_out": u["out"], "bytes_in": u["in"],
              "ratio": round(u["out"] / u["in"], 1) if u["in"] else None,
              "flows": u["flows"]}
             for ip, u in updown.items() if u["out"] > 0]
    exfil.sort(key=lambda x: -x["bytes_out"])

    # 3) DNS 없는 직결: dns 응답에 등장한 적 없는 외부 IP 접속 (하드코딩 C2 후보).
    #    주의: 짧은 캡처는 DNS 캐시 때문에 정상도 걸림 → 판단은 LLM 이 캡처 길이 보고.
    answered = set()
    for d in dns_recs:
        for a in d.get("answers") or []:
            answered.add(a)
    nodns = defaultdict(lambda: {"conns": 0, "ports": Counter(), "first_ts": None})
    for d in ext:
        ip = d["id.resp_h"]
        if ip in answered:
            continue
        e = nodns[ip]
        e["conns"] += 1
        e["ports"][d.get("id.resp_p")] += 1
        ts = d.get("ts")
        if ts and (e["first_ts"] is None or ts < e["first_ts"]):
            e["first_ts"] = ts
    no_dns_direct = [{"dst": ip, "conns": e["conns"], "first_ts": e["first_ts"],
                      "ports": [p for p, _ in e["ports"].most_common(3)]}
                     for ip, e in nodns.items()]
    no_dns_direct.sort(key=lambda x: -x["conns"])

    # 4) odd-port 외부 연결: 잘 알려진 포트 밖으로 나가는 트래픽 (:65400, :2222 류).
    odd = defaultdict(lambda: {"conns": 0, "first_ts": None})
    for d in ext:
        p = d.get("id.resp_p")
        if p is None or p in WELL_KNOWN_PORTS:
            continue
        e = odd[(d["id.resp_h"], p)]
        e["conns"] += 1
        ts = d.get("ts")
        if ts and (e["first_ts"] is None or ts < e["first_ts"]):
            e["first_ts"] = ts
    odd_ports = [{"dst": ip, "port": p, "conns": e["conns"], "first_ts": e["first_ts"]}
                 for (ip, p), e in odd.items()]
    odd_ports.sort(key=lambda x: -x["conns"])

    # 5) 역할 이탈: 워크스테이션이 SMTP/IRC/RDP 등으로 외부 발신 (역할×행동 기준선).
    ws = {ip for ip, h in hosts.items() if h.get("role") == "workstation"}
    dev = defaultdict(lambda: {"conns": 0, "dsts": set()})
    for d in ext:
        src, p = d.get("id.orig_h"), d.get("id.resp_p")
        if src in ws and p in WS_ODD_EGRESS_PORTS:
            e = dev[(src, p)]
            e["conns"] += 1
            e["dsts"].add(d["id.resp_h"])
    role_deviation = [{"src": src, "port": p, "service": WS_ODD_EGRESS_PORTS[p],
                       "conns": e["conns"], "distinct_dsts": len(e["dsts"])}
                      for (src, p), e in dev.items()]
    role_deviation.sort(key=lambda x: -x["conns"])

    # 6) 내부 fan-out: 한 호스트가 관리 포트로 다수 내부 호스트 접촉 (스캔/측면이동 후보).
    fan = defaultdict(set)
    for d in conn:
        if d.get("local_orig") and d.get("local_resp") \
           and d.get("id.resp_p") in LATERAL_PORTS:
            fan[d["id.orig_h"]].add(d["id.resp_h"])
    internal_fanout = [{"src": src, "distinct_dsts": len(dsts)}
                       for src, dsts in fan.items()
                       if len(dsts) >= ANOM_FANOUT_MIN_DSTS]
    internal_fanout.sort(key=lambda x: -x["distinct_dsts"])

    # 7) DNS 집계: NXDOMAIN 비율(DGA), TXT 다발(터널링), 고엔트로피 질의.
    total_q = len(dns_recs)
    nx = sum(1 for d in dns_recs if d.get("rcode_name") == "NXDOMAIN")
    txt = sum(1 for d in dns_recs if d.get("qtype_name") == "TXT")
    ent = []
    for q in {d.get("query") for d in dns_recs if d.get("query")}:
        label = q.split(".")[0]
        if len(label) >= 8:
            e = shannon_entropy(label)
            if e >= ANOM_ENTROPY_MIN:
                ent.append({"query": q, "entropy": e})
    ent.sort(key=lambda x: -x["entropy"])

    cap = ANOM_LIST_CAP
    return {
        "_floors": {"beacon_min_conns": ANOM_BEACON_MIN_CONNS,
                    "fanout_min_dsts": ANOM_FANOUT_MIN_DSTS,
                    "entropy_min": ANOM_ENTROPY_MIN, "list_cap": cap,
                    "note": "measurements only — maliciousness is NOT judged here"},
        "beacons": beacons[:cap],
        "exfil_candidates": exfil[:cap],
        "no_dns_direct": no_dns_direct[:cap],
        "odd_ports": odd_ports[:cap],
        "role_deviation": role_deviation[:cap],
        "internal_fanout": internal_fanout[:cap],
        "dns": {"total_queries": total_q, "nxdomain": nx,
                "nxdomain_rate": round(nx / total_q, 3) if total_q else None,
                "txt_queries": txt, "high_entropy": ent[:5]},
    }


# SMB 파일 action 중 "쓰기" 계열 (원격 페이로드 투하 = 실제 실행 신호)
SMB_WRITE_ACTIONS = ("WRITE", "PUT", "CREATE")


def build_lateral_movement(Z, hosts, read_ndjson):
    """내부↔내부 flow를 (src,dst)별로 묶고 실제 operation/share/write 를 부착한다.

    원칙(대화에서 확정): 코드는 '무엇을 했나(operation)'라는 팩트만 배달하고,
    '그게 공격이냐'는 판단하지 않는다(LLM 몫). dst 역할로만 버킷을 나눈다:
      - ad_authentication         : dst가 DC/DNS → 정상 AD 인증/조회 (측면이동 아님)
      - workstation_to_workstation: dst가 워크스테이션 → 진짜 측면이동 후보
      - unclassified              : dst 역할 불명

    핵심: dcerpc operation 을 pair 에 붙여야 'svcctl OpenSCManager2(정찰)'와
    'svcctl CreateServiceW(원격 실행)'가 구분됨. 집계된 endpoint 목록으론 불가능.
    smb_writes(ADMIN$/C$ 쓰기)는 실제 페이로드 투하의 강한 팩트라 함께 노출.
    """
    pair = defaultdict(lambda: {"dcerpc_ops": Counter(), "smb_shares": set(),
                                "smb_writes": [], "events": 0})

    for d in read_ndjson(f"{Z}/dce_rpc.log"):
        s, dst, op = d.get("id.orig_h"), d.get("id.resp_h"), d.get("operation")
        if s in hosts and dst in hosts and s != dst and op:
            p = pair[(s, dst)]
            p["dcerpc_ops"][op] += 1
            p["events"] += 1

    for d in read_ndjson(f"{Z}/smb_mapping.log"):
        s, dst = d.get("id.orig_h"), d.get("id.resp_h")
        if s in hosts and dst in hosts and s != dst:
            p = pair[(s, dst)]
            p["events"] += 1
            if d.get("share_type"):
                p["smb_shares"].add(d["share_type"])

    for d in read_ndjson(f"{Z}/smb_files.log"):
        s, dst = d.get("id.orig_h"), d.get("id.resp_h")
        act = (d.get("action") or "").upper()
        if s in hosts and dst in hosts and s != dst \
           and any(w in act for w in SMB_WRITE_ACTIONS):
            path = d.get("path") or d.get("name")
            if path:
                pair[(s, dst)]["smb_writes"].append(path)

    buckets = {"ad_authentication": [], "workstation_to_workstation": [],
               "unclassified": []}
    for (s, dst), p in pair.items():
        role = hosts[dst].get("role")
        entry = {"src": s, "dst": dst, "dst_role": role, "events": p["events"],
                 "dcerpc_ops": [op for op, _ in p["dcerpc_ops"].most_common(12)],
                 "smb_shares": sorted(p["smb_shares"]),
                 "smb_writes": p["smb_writes"][:5]}
        if role in ("domain_controller", "dns_server"):
            buckets["ad_authentication"].append(entry)
        elif role == "workstation":
            buckets["workstation_to_workstation"].append(entry)
        else:
            buckets["unclassified"].append(entry)
    for k in ("ad_authentication", "workstation_to_workstation", "unclassified"):
        buckets[k].sort(key=lambda x: -x["events"])

    buckets["_note"] = ("dcerpc_ops/smb_writes are facts, not verdicts. svcctl "
                        "OpenSCManager2 alone is a probe; CreateServiceW or an "
                        "ADMIN$/C$ smb_write is actual remote execution. "
                        "ad_authentication is normal AD traffic toward infra.")
    return buckets


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
    #   디코더 진단(checksum 등)은 위협이 아니므로 분리 — alert_cids(하드 시그널)에도 제외
    eve = read_ndjson(f"{S}/eve.json")
    alert_cids = set()
    sig_stat = {}                # (sig,cat,sev) -> dict(count, first_ts, src, dst, cids)
    diag_stat = Counter()        # 진단 시그니처 -> count
    for d in eve:
        if d.get("event_type") != "alert":
            continue
        a = d.get("alert", {})
        if is_capture_diagnostic(a.get("signature"), a.get("category")):
            diag_stat[a.get("signature")] += 1
            continue
        cid = d.get("community_id")
        alert_cids.add(cid)
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

    # ── 측면이동 로그: uid 집합 (하드 시그널 판정용). 프로파일은 role 확정 후 조립 ──
    #   (lateral_movement 구조는 dst 역할이 필요 → hosts/role 확정 뒤 build_lateral_movement)
    lm_uids = set()
    for lg in LM_LOGS:
        for r in read_ndjson(f"{Z}/{lg}"):
            if r.get("uid"):
                lm_uids.add(r["uid"])

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
                                     "scope": "internal", "role": None,
                                     "first_ts": None, "last_ts": None})

    for d in conn:
        ts = d.get("ts")
        for ipk, mack, localk in [("id.orig_h", "orig_l2_addr", "local_orig"),
                                  ("id.resp_h", "resp_l2_addr", "local_resp")]:
            ip = d.get(ipk)
            if not (d.get(localk) and is_real_host(ip)
                    and is_unicast_mac(d.get(mack))):
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

    # ── host role (결정론적: 프로토콜 역할로 판정, 추론 아님) ──
    #   domain_controller = kerberos/ldap 의 최다 목적지(내부)  (KDC/LDAP 서버 = 정의상 DC)
    #   dns_server        = DNS(:53) 최다 응답자(내부); 보통 DC 와 동일 → DC 우선
    #   workstation       = kerberos 사용자 계정이 있는 내부 호스트
    #   그 외(게이트웨이 등)은 규칙이 불확실 → role=None (추론 안 함)
    def top_internal_resp(logs):
        c = Counter()
        for lg in logs:
            for d in read_ndjson(f"{Z}/{lg}") or []:
                rh = d.get("id.resp_h")
                if rh in hosts:                       # 내부 호스트만
                    c[rh] += 1
        return c.most_common(1)[0][0] if c else None

    dc_ip = top_internal_resp(["kerberos.log", "ldap.log", "ldap_search.log"])
    dns_ip = top_internal_resp(["dns.log"])
    for ip, h in hosts.items():
        if ip == dc_ip:
            h["role"] = "domain_controller"
        elif ip == dns_ip:
            h["role"] = "dns_server"
        elif h["username"]:
            h["role"] = "workstation"

    # ── 측면이동 프로파일: (src,dst)별 실제 operation/share/write 부착, dst 역할로 분류 ──
    lateral_movement = build_lateral_movement(Z, hosts, read_ndjson)

    # ── external (목표2/4/5): ip/도메인/sni + first_ts ──
    ext_ip = {}          # ip -> {first_ts, conns}
    for d in conn:
        if d.get("local_resp") is False:
            ip = d.get("id.resp_h"); ts = d.get("ts")
            e = ext_ip.setdefault(ip, {"ip": ip, "first_ts": None, "conns": 0})
            e["conns"] += 1
            if ts and (e["first_ts"] is None or ts < e["first_ts"]):
                e["first_ts"] = ts

    dns_recs = read_ndjson(f"{Z}/dns.log")
    ext_dom = {}         # query -> {first_ts, answers}
    for d in dns_recs:
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
        "capture_diagnostics": [{"signature": s, "count": c}
                                for s, c in diag_stat.most_common()],
        "files": files,
        "external": external,
        "lateral_movement": lateral_movement,
        "anomalies": build_anomalies(conn, hosts, dns_recs),
        "_truncation": trunc,
    }
    # 모든 내부 계산(주기/duration/정렬)이 끝난 뒤 마지막에 한 번만 형식 통일
    return normalize_ts(evidence)


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
    an = ev["anomalies"]
    print(f"  hosts={len(ev['hosts'])} alerts={len(ev['alerts'])} "
          f"diag={sum(d['count'] for d in ev['capture_diagnostics'])} "
          f"files={len(ev['files'])} ext_ip={len(ev['external']['ips'])} "
          f"ext_dom={len(ev['external']['domains'])} sni={len(ev['external']['sni'])}")
    print(f"  anomalies: beacons={len(an['beacons'])} exfil={len(an['exfil_candidates'])} "
          f"no_dns={len(an['no_dns_direct'])} odd_ports={len(an['odd_ports'])} "
          f"role_dev={len(an['role_deviation'])} fanout={len(an['internal_fanout'])}")
    if ev["_truncation"]:
        print(f"  _truncation={ev['_truncation']}")


if __name__ == "__main__":
    main()
