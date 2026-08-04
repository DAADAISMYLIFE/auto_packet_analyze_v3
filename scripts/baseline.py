#!/usr/bin/env python3
"""결정론 편차(deviation) 엔진 — "정상을 알고 편차만 본다".

철학: 탐지의 뼈대는 결정론 코드가 진다(코드 강점). 각 외부 목적지/호스트 행동을 '정상
(baseline) 대비 얼마나 튀는가'로 점수화해서, LLM 이 raw 덤프가 아니라 '튀는 것'부터 보게
한다. 이렇게 하면 (1) 대용량에서 신호가 먼저 살아남고(잘림 방어), (2) 정상 AD RPC·MS
텔레메트리·광고·CDN 은 baseline 딱지가 붙어 오탐이 뿌리에서 죽는다.

위협 판정 = 숫자 severity 가 아니라 시그니처 '카테고리'로 한다 — ET 룰의 severity 는
못 믿는다(ET CHAT Skype 가 sev1). MALWARE/EXPLOIT/WEB_SERVER/SCAN/CURRENT_EVENTS 등은
위협, INFO/POLICY/CHAT/FILE_SHARING 은 앱 정황(위협 아님). 이 분류는 범용(케이스 무관).

signal 을 hard/soft 로 나눈다:
  hard  위협-카테고리 alert · DNS터널 · 의심TLD · 고비율 유출  → 무조건 표면화
  soft  beacon · 저비율 유출 · 미분류 alert                    → known-normal 이면 억제
known-normal 은 soft 를 무시하고 hard 만 본다. 그래서:
  - MS 텔레메트리가 주기적으로 beacon/업로드해도(soft) baseline 으로 강등(오탐 죽음).
  - 광고망/CDN 이 MALWARE 로 악용(hard)되면 그래도 표면화(malvertising 안 놓침).

산출물(evidence["deviations"]):
  top / host_deviations / baseline_suppressed / ad_rpc  (아래 profile_deviations 참조)
사용: python scripts/baseline.py output/<case>
"""
import json
import os
import re
import sys
import ipaddress

# ── 큐레이트된 known-normal 도메인(부분일치). soft 신호만 억제(hard 는 그대로 뜬다). ──
KNOWN_NORMAL_DOM = (
    "microsoft.com", "windows.com", "windowsupdate.com", "msftconnecttest.com",
    "msftncsi.com", "msft", "office.com", "office.net", "live.com", "msn.com",
    "bing.com", "azure", "azureedge.net", "windows.net", "msedge.net",
    "skype.com", "teams", "microsoftapp.net", "wns.windows.com",
    "google.com", "googleapis.com", "gstatic.com", "gvt1.com", "youtube.com",
    "google-analytics.com", "doubleclick.net", "googlesyndication.com",
    "client-channel.google.com", "apple.com", "icloud.com", "mozilla.",
    "digicert.com", "verisign.com", "globalsign.com", "letsencrypt.org",
    "sectigo.com", "akamai", "akadns.net", "cloudflare.com", "fastly.net",
    "dropbox.com", "facebook.com", "fbcdn.net", "clarity.ms", "adobe.com",
    "ubuntu.com", "debian.org", "cloudfront.net", "office365.com",
    # 광고/트래커 — 조용하면 노이즈(soft, 강등), MALWARE 로 악용되면(hard) 표면화
    "adnxs.com", "adsafeprotected.com", "betrad.com", "madadsmedia.com",
    "pubmatic.com", "moatads.com", "scorecardresearch.com", "rubiconproject.com",
    "casalemedia.com", "adsrvr.org", "3lift.com", "amazon-adsystem.com",
    "advertising.com", "adform.net", "criteo.com", "taboola.com",
)
_NORMAL_NETS = [ipaddress.ip_network(c) for c in (
    "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",  # Cloudflare
    "151.101.0.0/16",                                                     # Fastly
)]
SUSP_TLD = re.compile(r"\.(su|cc|cyou|xyz|top|tk|gq|ml|cf|ga)$")
_IPV4 = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")

# 시그니처 카테고리 → 위협 여부 (숫자 severity 불신). ET/GPL 룰 접두 카테고리 기반.
_CAT_THREAT = re.compile(
    r"\b(MALWARE|TROJAN|CNC|COINMINER|EXPLOIT|ATTACK_RESPONSE|WEB_SERVER|"
    r"WEB_SPECIFIC_APPS|CURRENT_EVENTS|SCAN|PHISHING|WORM|ROOTKIT|DOS|"
    r"SHELLCODE|MOBILE_MALWARE)\b", re.I)
_CAT_RAT = re.compile(r"\bREMOTE_ACCESS\b", re.I)
_CAT_BENIGN = re.compile(
    r"\b(INFO|POLICY|CHAT|P2P|FILE_SHARING|VOIP|GAMES|MISC_ACTIVITY|"
    r"USER_AGENTS|TFTP|DNS)\b", re.I)


def _cat_weight(sig):
    """시그니처 카테고리 → (hard 가중치, soft 가중치). 위협=hard, 앱정황=0, 미분류=soft."""
    if _CAT_THREAT.search(sig):
        return 4, 0
    if _CAT_RAT.search(sig):
        return 3, 0                       # RAT — 실제 위협(NetSupport 등)
    if _CAT_BENIGN.search(sig):
        return 0, 0                       # INFO/CHAT/FILE_SHARING = 앱 정황, 위협 아님
    return 0, 1                           # 미분류 = 약한 신호


def _is_normal_ip(ip):
    try:
        return any(ipaddress.ip_address(ip) in n for n in _NORMAL_NETS)
    except ValueError:
        return False


def _known_normal_dom(d):
    d = d.lower()
    return any(k in d for k in KNOWN_NORMAL_DOM)


def _parent(d):
    parts = d.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else d.lower()


def _dns_tunnel_parents(ev):
    """한 부모 밑 고엔트로피 서브도메인 여럿 = DNS 터널/exfil(예: *.pwned.se)."""
    he = (((ev.get("anomalies") or {}).get("dns") or {}).get("high_entropy")) or []
    groups = {}
    for q in he:
        query = str(q.get("query") or "")
        if "." in query:
            groups.setdefault(_parent(query), []).append(query)
    return {p: c for p, c in groups.items()
            if len(c) >= 2 and not _known_normal_dom(p)}


def profile_deviations(ev, top_k=25):
    hosts = ev.get("hosts", []) or []
    internal = {str(h.get("ip")).lower() for h in hosts if h.get("ip")}
    ext = ev.get("external", {}) or {}
    an = ev.get("anomalies", {}) or {}

    # ── IP별 alert 카테고리 가중치 인덱스 ──
    ip_hard, ip_soft, ip_sig = {}, {}, {}
    for a in ev.get("alerts", []) or []:
        sig = a.get("signature") or ""
        hw, sw = _cat_weight(sig)
        for ip in (a.get("src_ips") or []) + (a.get("dst_ips") or []):
            s = str(ip).lower()
            if s in internal:
                continue
            if hw > ip_hard.get(s, 0):
                ip_hard[s] = hw; ip_sig[s] = sig[:44]
            ip_soft[s] = max(ip_soft.get(s, 0), sw)
    beacon_ip = {str(b.get("dst")).lower() for b in (an.get("beacons") or []) if b.get("dst")}
    exfil_ratio = {str(x.get("dst")).lower(): x.get("ratio") or 0
                   for x in (an.get("exfil_candidates") or []) if x.get("dst")}
    tunnels = _dns_tunnel_parents(ev)

    def ip_signals(ip):
        """IP 하나의 (hard, soft, reasons). alert=카테고리별, beacon/exfil=행동."""
        hard, soft, why = 0, 0, []
        if ip_hard.get(ip):
            hard += ip_hard[ip]; why.append(f"alert:{ip_sig.get(ip,'')}")
        elif ip_soft.get(ip):
            soft += ip_soft[ip]; why.append("alert:미분류")
        if ip in beacon_ip:
            soft += 2; why.append("beacon")
        r = exfil_ratio.get(ip, 0)
        if r >= 10:
            hard += 3; why.append(f"exfil(ratio{r})")
        elif r >= 2:
            soft += 1; why.append(f"exfil(ratio{r})")
        return hard, soft, why

    # ── 도메인 목적지(DNS query + TLS SNI) ──
    dom_answers = {}
    for d in ext.get("domains", []) or []:
        q = str(d.get("query") or "").lower()
        if q:
            dom_answers.setdefault(q, [])
            for a in (d.get("answers") or []):
                if a and _IPV4.fullmatch(str(a)):
                    dom_answers[q].append(str(a).lower())
    for s in ext.get("sni", []) or []:
        sni = str((s.get("sni") if isinstance(s, dict) else s) or "").lower()
        if sni:
            dom_answers.setdefault(sni, [])
    answer_ips = {ip for ips in dom_answers.values() for ip in ips}

    devs, baseline = [], []

    def emit(dest, kind, hard, soft, reasons, normal):
        # known-normal 은 soft(행동) 무시, hard 만. 그 외는 hard+soft.
        score = hard if normal else hard + soft
        if normal and hard > 0:
            reasons = reasons + ["!known-normal 인데 위협신호(hard) — 악용 의심"]
        if score > 0:
            devs.append({"dest": dest, "kind": kind, "score": round(score, 1),
                         "reasons": reasons})
        elif normal:
            baseline.append(dest)
        else:
            devs.append({"dest": dest, "kind": kind, "score": 0.5,
                         "reasons": ["미분류 외부(위협신호 없음)"]})

    # 부모(등록도메인)별로 묶는다 — DNS터널/DGA 는 서브도메인이 top 을 도배하지 않게 부모 1개로 접음.
    by_parent = {}
    for dom in dom_answers:
        if dom not in internal:
            by_parent.setdefault(_parent(dom), []).append(dom)

    emitted_ips = set()

    def best_ip_sig(doms):
        bh, bs, bw = 0, 0, []
        for dm in doms:
            for ip in dom_answers.get(dm, []):
                emitted_ips.add(ip)
                h, s, w = ip_signals(ip)
                if h + s > bh + bs:
                    bh, bs, bw = h, s, w
        return bh, bs, bw

    for par, members in by_parent.items():
        susp = [m for m in members if SUSP_TLD.search(m)]
        collapse = (par in tunnels) or (len(members) >= 3 and len(susp) >= 3)
        if collapse:                       # 터널/DGA 부모 1개로 접기(서브도메인 도배 방지)
            hard = 4 if par in tunnels else 2
            why = [(f"dns-tunnel(*.{par})" if par in tunnels else f"suspicious-TLD 다수(*.{par})"),
                   f"{len(members)}개 서브도메인"]
            bh, bs, bw = best_ip_sig(members)
            emit(par, "domain", hard + bh, bs, why + bw, False)
        else:
            for dom in members:
                hard, why = (2, ["suspicious-TLD"]) if SUSP_TLD.search(dom) else (0, [])
                bh, bs, bw = best_ip_sig([dom])
                emit(dom, "domain", hard + bh, bs, why + bw, _known_normal_dom(dom))

    for x in ext.get("ips", []) or []:
        ip = str(x.get("ip") or "").lower()
        if not ip or ip in internal or ip in answer_ips or ip in emitted_ips:
            continue
        emitted_ips.add(ip)
        h, s, w = ip_signals(ip)
        emit(ip, "ip", h, s, w, _is_normal_ip(ip))

    # 위협-카테고리 alert 가 걸렸는데 external.ips 에 없던 IP(인바운드 공격자·캡에서 드롭된 C2)도 표면화.
    for ip in ip_hard:
        if ip in internal or ip in answer_ips or ip in emitted_ips:
            continue
        emitted_ips.add(ip)
        h, s, w = ip_signals(ip)
        emit(ip, "ip", h, s, w, _is_normal_ip(ip))

    devs.sort(key=lambda r: -r["score"])

    # ── 호스트 행동편차: '공격 후 안 하던 짓 시작'(침해/성공의 결정론 신호) ──
    #   alert 출발지는 위협-카테고리만(Skype/Dropbox CHAT alert 로 오염 방지).
    host_dev = {}
    hostname_of = {str(h.get("ip")).lower(): (h.get("hostname") or "") for h in hosts}
    for a in ev.get("alerts", []) or []:
        if _cat_weight(a.get("signature") or "")[0] == 0:      # 위협 카테고리만
            continue
        srcs = {str(s).lower() for s in (a.get("src_ips") or [])}
        dsts = {str(d).lower() for d in (a.get("dst_ips") or [])}
        for s in srcs & internal:
            if dsts - internal:
                host_dev.setdefault(s, set()).add(
                    f"위협 alert 출발지→외부: {(a.get('signature') or '')[:40]}")
    for ip, hn in hostname_of.items():
        for p, children in tunnels.items():
            if hn and any(hn.lower() in c for c in children):
                host_dev.setdefault(ip, set()).add(f"DNS 터널 출발지(*.{p})")
    for c in ((an.get("brute_force") or {}).get("conn_rate") or []):
        s = str(c.get("src") or "").lower()
        if s in internal and (c.get("conns") or 0) >= 100 and (c.get("port") not in (53,)):
            host_dev.setdefault(s, set()).add(
                f"고빈도 연결 {c.get('conns')}회→{c.get('dst')}:{c.get('port')}")
    host_deviations = [{"ip": ip, "changes": sorted(v)} for ip, v in host_dev.items()]

    # ── AD RPC baseline: DCSync 아니면 정상 인증(자폭 방지) ──
    lm_text = json.dumps(ev.get("lateral_movement") or {}) + json.dumps(ev.get("signals") or {})
    dcsync = bool(re.search(r"DRSGetNCChanges|GetNCChanges", lm_text, re.I))
    ad_rpc = {"baseline": not dcsync,
              "note": ("DCSync(DRSGetNCChanges) 관측 — 실제 자격증명 복제 공격" if dcsync else
                       "워크→DC RPC(DRSCrackNames/SAMR/LSA)는 정상 도메인 인증 = baseline. "
                       "공격 판단 금지(DC 격리 자폭 방지).")}

    return {
        "top": devs[:top_k],
        "host_deviations": host_deviations,
        "baseline_suppressed": {"count": len(baseline), "sample": sorted(baseline)[:10]},
        "ad_rpc": ad_rpc,
    }


def main():
    if len(sys.argv) < 2:
        raise SystemExit("사용법: python scripts/baseline.py output/<case>")
    ev = json.load(open(os.path.join(sys.argv[1], "evidence.json"), encoding="utf-8"))
    d = profile_deviations(ev)
    print(f"\n[ad_rpc] baseline={d['ad_rpc']['baseline']}")
    print(f"[baseline 강등] {d['baseline_suppressed']['count']}개  "
          f"{d['baseline_suppressed']['sample']}")
    print("[host 행동편차]")
    for h in d["host_deviations"]:
        print(f"   {h['ip']}: {'; '.join(h['changes'])}")
    print("[top 편차 = 사건]")
    for r in d["top"]:
        if r["score"] >= 1:
            print(f"   {r['score']:>4}  {r['kind']:<6} {r['dest'][:46]:<46} {r['reasons']}")


if __name__ == "__main__":
    main()
