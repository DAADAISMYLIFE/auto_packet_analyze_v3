#!/usr/bin/env python3
"""정답(truth) 초안 생성 — evidence.json 이 준 후보만 추려 라벨 시트를 만든다.

무에서 정답을 쓰는 게 아니라, 코드가 후보를 좁히고 사람은 o/x 만 찍는다.
(이 저장소의 "사람은 마지막에 선택만 한다" 철학을 채점 데이터 만들기에도 적용)

정답은 한 번에 완성할 필요가 없다 — score.py 는 없는 필드를 None 으로 처리하므로
`{"case": X, "verdict": "confirmed"}` 한 줄만으로도 verdict + grounding(환각) 이 측정된다.
  L0  verdict 만                       → 30초.  verdict / ground 채점 시작
  L1  + victims / infra_ips / pz       → 이 스크립트가 초안 생성, 사람이 검수
  L2  + iocs 라벨링                    → 후보에서 아닌 것만 지운다

사용법
  python scripts/make_truth.py output/<case>            # 후보 시트만 출력
  python scripts/make_truth.py output/<case> --write    # answers/truth/<case>.json 초안 저장
  python scripts/make_truth.py output/<case> --l0       # verdict 만 있는 최소 정답 저장
  python scripts/make_truth.py --all                    # output/* 전체에서 truth 없는 케이스만
  python scripts/make_truth.py output/<case> --verify   # 기존 truth 와 후보 커버리지 대조
"""
import argparse
import json
import os
import re
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRUTH_DIR = os.path.join(ROOT, "answers", "truth")
OUTPUT_DIR = os.path.join(ROOT, "output")

# 여기서 받은 파일은 악성 후보에서 빼고 benign_hashes 로 넣는다.
#   (WU/Defender 업데이트 해시를 iocs 에 올리면 차단정책이 MS 업데이트를 막는 오탐 —
#    score.py 의 fp 축이 잡는 실패다. 후보 단계에서 미리 갈라둔다.)
#   OS·오피스 텔레메트리는 beacon/exfil 신호를 대량으로 만들지만 전부 정상이다.
TRUSTED = ("windowsupdate.com", "microsoft.com", "windows.com", "msftconnecttest.com",
           "office.com", "office.net", "officeapps.live.com", "live.com", "msn.com",
           "bing.com", "azureedge.net", "windows.net", "msedge.net", "skype.com",
           "digicert.com", "verisign.com", "globalsign.com", "letsencrypt.org", "sectigo.com",
           "mozilla.", "google.com", "googleapis.com", "gvt1.com", "gstatic.com", "youtube.com",
           "apple.com", "icloud.com", "adobe.com", "ubuntu.com", "debian.org", "akadns.net")

# IOC 후보에서 뺄 파일 타입 (본문·이미지·인증서·정책파일은 페이로드가 아니다)
BORING_MIME = ("text/html", "text/plain", "text/xml", "text/ini", "text/json",
               "image/png", "image/jpeg", "image/gif", "image/x-icon", "image/webp",
               "application/ocsp-response", "application/json", "application/vnd.ms-pol",
               "application/pkix-crl", None)


# ─────────────────────────── 로딩 ───────────────────────────
def case_key(stem):
    """디렉터리명 → truth 파일 키 (score.py case_of 와 같은 규칙)."""
    d = re.sub(r"\D", "", stem)
    return d[:8] if len(d) >= 8 else stem


def load_evidence(case_dir):
    path = os.path.join(case_dir, "evidence.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ─────────────────────────── 후보 추출 ───────────────────────────
def external_candidates(ev):
    """외부 IP 후보 → {ip: {"alert": [...], "beacon": [...], "exfil": [...]}}

    외부 IP 전수(수백 개)를 사람에게 보여주면 라벨링이 불가능하므로 세 신호로 좁힌다.
      alert   시그니처가 걸린 IP           — 알려진 위협
      beacon  주기적 통신 (C2 비컨)        — 시그니처 없는 C2 를 잡는다
      exfil   유출 의심 (bytes_out 편중)

    alert 하나만 쓰면 Cloudflare 뒤에 숨은 C2(2025-06-13 케이스)를 통째로 놓친다.
    실측: alert 단독 3/5 → 세 신호 합집합 5/5.
    """
    internal = {h["ip"] for h in ev.get("hosts", []) if h.get("ip")}
    cand = defaultdict(lambda: defaultdict(list))

    for a in ev.get("alerts", []):
        for ip in (a.get("dst_ips") or []) + (a.get("src_ips") or []):
            if ip and ip not in internal:
                cand[ip]["alert"].append((a.get("severity"), a.get("signature") or "", a.get("count") or 0))

    an = ev.get("anomalies", {}) or {}
    for b in an.get("beacons") or []:
        ip = b.get("dst")
        if ip and ip not in internal:
            cand[ip]["beacon"].append(
                (f"주기 {b.get('interval_avg_s')}s jitter {b.get('jitter_pct')}%", b.get("conns") or 0))
    for x in an.get("exfil_candidates") or []:
        ip = x.get("dst")
        if ip and ip not in internal:
            cand[ip]["exfil"].append(
                (f"out {x.get('bytes_out')}B in {x.get('bytes_in')}B", x.get("flows") or 0))

    return cand


def prune_trusted(cand, ip2dom):
    """행동신호(beacon/exfil)만으로 올라온 IP 중 신뢰 도메인으로만 해석되는 것을 뺀다.

    exfil_candidates 는 MS 텔레메트리·구글 등 정상 대용량 업로드를 대량으로 물고 온다.
    alert 가 걸린 IP 는 신뢰 도메인이어도 남긴다(공격자가 정상 CDN 을 악용한 경우).
    """
    dropped = {}
    for ip in list(cand):
        if cand[ip].get("alert"):
            continue
        doms = ip2dom.get(ip) or set()
        if doms and all(any(t in d for t in TRUSTED) for d in doms):
            dropped[ip] = sorted(doms)
            del cand[ip]
    return dropped


def domains_resolving_to(ev, ips):
    """후보 IP 로 해석된 도메인 (DNS query→answers 조인) → {domain: {ip, ...}}"""
    out = defaultdict(set)
    for d in ev.get("external", {}).get("domains", []) or []:
        q = d.get("query")
        if not q:
            continue
        for a in (d.get("answers") or []):
            if a in ips:
                out[q].add(a)
    return out


def domains_from_files(ev, hashes):
    """악성 후보 파일을 서빙한 호스트명 (url 앞부분) — DNS 없이 직접 접속한 경로도 잡는다."""
    out = set()
    for f in ev.get("files", []):
        if f.get("sha256") in hashes and f.get("url"):
            host = f["url"].split("/")[0].lower()
            if host and not re.fullmatch(r"[\d.]+", host):     # IP 는 도메인 아님
                out.add(host)
    return out


def split_files(ev):
    """실행/압축류 파일을 악성 후보와 신뢰출처(benign)로 가른다."""
    mal, benign = [], []
    for f in ev.get("files", []):
        if not f.get("sha256") or f.get("mime") in BORING_MIME:
            continue
        url = (f.get("url") or "").lower()
        (benign if any(t in url for t in TRUSTED) else mal).append(f)
    return mal, benign


def alerted_internals(ev, workstations):
    """alert 의 src 로 등장한 내부 워크스테이션 → 감염 의심 (victims 초안).

    반환: {ip: [(severity, signature), ...]}  — 왜 의심인지 근거를 같이 보여준다.
    """
    ws = {h["ip"] for h in workstations}
    hit = defaultdict(list)
    for a in ev.get("alerts", []):
        for ip in (a.get("src_ips") or []) + (a.get("dst_ips") or []):
            if ip in ws:
                hit[ip].append((a.get("severity"), a.get("signature") or ""))
    return hit


def ip_to_domains(ev):
    """{ip: {domain, ...}} — DNS answers 역인덱스 (신뢰 도메인 가지치기용)."""
    out = defaultdict(set)
    for d in ev.get("external", {}).get("domains", []) or []:
        q = (d.get("query") or "").lower()
        for a in (d.get("answers") or []):
            if a and q:
                out[a].add(q)
    return out


def build(ev):
    hosts = [h for h in ev.get("hosts", []) if h.get("ip")]
    workstations = [h for h in hosts if h.get("role") == "workstation"]
    infra = [h for h in hosts if h.get("role") != "workstation"]

    cand = external_candidates(ev)
    dropped = prune_trusted(cand, ip_to_domains(ev))

    mal_files, benign_files = split_files(ev)
    mal_hashes = {f["sha256"] for f in mal_files}

    doms = domains_resolving_to(ev, set(cand))
    file_doms = domains_from_files(ev, mal_hashes) - set(doms)

    return {
        "hosts": hosts,
        "workstations": workstations,
        "infra": infra,
        "why": cand,
        "dropped": dropped,
        "doms": doms,
        "file_doms": file_doms,
        "mal_files": mal_files,
        "benign_files": benign_files,
        "hit_internal": alerted_internals(ev, workstations),
        "n_external_ips": len(ev.get("external", {}).get("ips", []) or []),
        "n_files": len(ev.get("files", []) or []),
    }


# ─────────────────────────── 라벨 시트 출력 ───────────────────────────
def _worst(rows):
    """가장 심각한 근거 하나 (severity 낮을수록 심각, 같으면 count 큰 것)."""
    return sorted(rows, key=lambda r: (r[0] if r[0] is not None else 9, -(r[-1] if len(r) > 2 else 0)))[0]


def _rank(sigs):
    """후보 정렬 키 — alert 있는 것 먼저, 그다음 beacon, 그다음 exfil."""
    if sigs.get("alert"):
        return (0, _worst(sigs["alert"])[0] if _worst(sigs["alert"])[0] is not None else 9)
    if sigs.get("beacon"):
        return (1, 0)
    return (2, 0)


def _why_line(sigs):
    """후보 한 줄 요약 — 왜 후보인지."""
    if sigs.get("alert"):
        sev, sig, cnt = _worst(sigs["alert"])
        return f"alert  sev{sev} x{cnt:<6} {sig[:48]}"
    if sigs.get("beacon"):
        desc, conns = sigs["beacon"][0]
        return f"beacon x{conns:<6} {desc}"
    desc, flows = sigs["exfil"][0]
    return f"exfil  x{flows:<6} {desc}"


def sheet(b, stem):
    print(f"\n{'='*72}\n  {stem}\n{'='*72}")

    print(f"\n[1] 내부 워크스테이션 {len(b['workstations'])}개 — victims 에 넣을 것 고르기 (*=alert 걸림)")
    if not b["workstations"]:
        print("    (없음 — hosts 에 workstation role 이 안 잡혔다. evidence 확인 필요)")
    for h in b["workstations"]:
        star = "*" if h["ip"] in b["hit_internal"] else " "
        print(f"  {star} {h['ip']:<16} {(h.get('hostname') or '-'):<20} {h.get('username') or '-'}")
        if h["ip"] in b["hit_internal"]:
            sev, sig = _worst(b["hit_internal"][h["ip"]])[:2]
            print(f"      └ sev{sev} {sig[:58]}")

    print(f"\n[2] 인프라 {len(b['infra'])}개 — infra_ips 자동 분류 (피해자로 부르면 자폭)")
    for h in b["infra"]:
        print(f"    {h['ip']:<16} role={h.get('role') or 'unknown'}")

    print(f"\n[3] 외부 IP 후보 {len(b['why'])}개 (전체 {b['n_external_ips']}개 → alert/beacon/exfil 로 축소)"
          f" — c2/delivery/exfil/무시 분류")
    for ip, sigs in sorted(b["why"].items(), key=lambda kv: _rank(kv[1])):
        print(f"    {ip:<16} {_why_line(sigs)}")
        for d in sorted(dd for dd, ips in b["doms"].items() if ip in ips):
            print(f"        └ {d}")
    if b["dropped"]:
        print(f"    (신뢰 도메인이라 제외된 행동신호 IP {len(b['dropped'])}개: "
              f"{', '.join(list(b['dropped'])[:4])}{' ...' if len(b['dropped']) > 4 else ''})")

    print(f"\n[4] 파일 해시 후보 {len(b['mal_files'])}개 (전체 {b['n_files']}개에서 축소) — iocs.hashes")
    for f in b["mal_files"]:
        print(f"    {f['sha256'][:16]} {(f.get('mime') or ''):<34} {(f.get('url') or '')[:52]}")
    if b["file_doms"]:
        print(f"    ↳ 위 파일을 서빙한 도메인(DNS 조인에 없던 것): {', '.join(sorted(b['file_doms']))}")

    print(f"\n[5] 신뢰출처 파일 {len(b['benign_files'])}개 — benign_hashes 자동 채움 (오탐 함정)")
    for f in b["benign_files"][:5]:
        print(f"    {f['sha256'][:16]} {(f.get('url') or '')[:56]}")
    if len(b["benign_files"]) > 5:
        print(f"    ... 외 {len(b['benign_files']) - 5}개")

    label_count = len(b["workstations"]) + len(b["why"]) + len(b["mal_files"])
    print(f"\n  → 라벨 대상 총 {label_count}개. patient_zero 만 직접 채우면 L2 완성.")


# ─────────────────────────── truth 초안 ───────────────────────────
#   verdict 는 코드가 추론하지 않는다. 파이프라인이 보는 것과 같은 신호로 정답을 만들면
#   verdict 축이 "LLM 이 내 휴리스틱과 일치하나"를 재는 순환논리가 된다. 사람이 정한다.
VERDICT_TODO = "REVIEW_ME"


def skeleton(case, b, l0=False, verdict=None):
    """L0 = verdict 만. L1/L2 = 후보를 전부 채워두고 사람이 지우는 방식(빈칸 채우기보다 빠름)."""
    if l0:
        return {"case": case,
                "source": "make_truth.py --l0 (verdict 만 — ground/verdict 축 채점용)",
                "verdict": verdict or VERDICT_TODO}

    hit = b["hit_internal"]
    return {
        "case": case,
        "source": "make_truth.py 초안 — 사람 검수 필요 (iocs 는 후보 전량이므로 아닌 것을 지울 것)",
        "verdict": verdict or VERDICT_TODO,           # no_incident / suspicious / confirmed
        "victims": [{"ip": h["ip"],
                     "hostname": h.get("hostname"),
                     "username": h.get("username")}
                    for h in b["workstations"] if h["ip"] in hit],
        "infra_ips": [h["ip"] for h in b["infra"]],
        "iocs": {
            "c2": sorted(b["why"]),                   # ← 아닌 것만 지운다
            "delivery": [],
            "exfil": [],
            "domains": sorted(set(b["doms"]) | b["file_doms"]),
            "hashes": [f["sha256"] for f in b["mal_files"]],
        },
        "benign_hashes": [f["sha256"] for f in b["benign_files"]],
        "patient_zero": "",                           # ← 사람이 채움 (비우면 pz 채점 스킵)
    }


def write_truth(key, data, force=False):
    os.makedirs(TRUTH_DIR, exist_ok=True)
    out = os.path.join(TRUTH_DIR, key + ".json")
    if os.path.exists(out) and not force:
        print(f"  [!] {os.path.relpath(out, ROOT)} 이미 있음 — 덮어쓰지 않는다 (--force)")
        return None
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"  [*] 저장: {os.path.relpath(out, ROOT)}")
    return out


# ─────────────────────────── 검증 (기존 truth 대조) ───────────────────────────
def verify(key, b):
    """후보 축소가 정답을 놓치지 않는지 기존 truth 로 확인한다."""
    tpath = os.path.join(TRUTH_DIR, key + ".json")
    if not os.path.exists(tpath):
        print(f"  (truth 없음 — 검증 스킵: {key})")
        return
    with open(tpath, encoding="utf-8") as f:
        t = json.load(f)
    ti = t.get("iocs", {})

    real_ips = {str(x).lower() for x in (ti.get("c2", []) + ti.get("delivery", []) + ti.get("exfil", []))}
    cand_ips = {ip.lower() for ip in b["why"]}
    real_h = {str(x).lower() for x in ti.get("hashes", [])}
    cand_h = {f["sha256"].lower() for f in b["mal_files"]}
    real_ben = {str(x).lower() for x in t.get("benign_hashes", [])}
    cand_ben = {f["sha256"].lower() for f in b["benign_files"]}
    real_vic = {str(v.get("ip", "")).lower() for v in t.get("victims", [])}
    cand_vic = {ip.lower() for ip in b["hit_internal"]}
    real_inf = {str(x).lower() for x in t.get("infra_ips", [])}
    cand_inf = {h["ip"].lower() for h in b["infra"]}

    def row(name, real, cand):
        if not real:
            print(f"    {name:<14} (truth 에 없음)")
            return
        miss = sorted(real - cand)
        cov = (len(real & cand) / len(real))
        flag = "OK " if not miss else "MISS"
        print(f"    {name:<14} {flag} 커버 {len(real & cand)}/{len(real)} ({cov:.0%})"
              f"  후보{len(cand)}개" + (f"  놓침={miss}" if miss else ""))

    print(f"\n  [검증] {key} — 후보가 정답을 덮는가")
    row("ioc IPs", real_ips, cand_ips)
    row("hashes", real_h, cand_h)
    row("benign_hash", real_ben, cand_ben)
    row("victims", real_vic, cand_vic)
    row("infra_ips", real_inf, cand_inf)


# ─────────────────────────── 드라이버 ───────────────────────────
def case_dirs(args):
    if args.all:
        dirs = []
        for name in sorted(os.listdir(OUTPUT_DIR)):
            d = os.path.join(OUTPUT_DIR, name)
            if not os.path.isdir(d) or not os.path.exists(os.path.join(d, "evidence.json")):
                continue
            if args.missing_only and os.path.exists(os.path.join(TRUTH_DIR, case_key(name) + ".json")):
                continue
            dirs.append(d)
        return dirs
    return [args.case_dir]


def main():
    ap = argparse.ArgumentParser(description="evidence.json → truth 후보 시트/초안")
    ap.add_argument("case_dir", nargs="?", help="output/<case> 디렉터리")
    ap.add_argument("--all", action="store_true", help="output/* 전체 처리")
    ap.add_argument("--missing-only", action="store_true", help="--all 과 함께: truth 없는 케이스만")
    ap.add_argument("--write", action="store_true", help="answers/truth/<key>.json 초안 저장")
    ap.add_argument("--l0", action="store_true", help="verdict 만 있는 최소 정답 저장")
    ap.add_argument("--verdict", choices=["no_incident", "suspicious", "confirmed"],
                    help="정답 verdict (안 주면 REVIEW_ME 로 두고 경고 — 코드가 추론하지 않는다)")
    ap.add_argument("--force", action="store_true", help="기존 truth 덮어쓰기")
    ap.add_argument("--verify", action="store_true", help="기존 truth 로 후보 커버리지 검증")
    ap.add_argument("--quiet", action="store_true", help="시트 출력 생략")
    args = ap.parse_args()

    if not args.all and not args.case_dir:
        ap.error("case_dir 또는 --all 필요")

    todo = []
    for d in case_dirs(args):
        stem = os.path.basename(d.rstrip("/"))
        ev = load_evidence(d)
        if ev is None:
            print(f"[skip] {stem}: evidence.json 없음")
            continue
        b = build(ev)
        if not args.quiet:
            sheet(b, stem)
        if args.verify:
            verify(case_key(stem), b)
        if args.write or args.l0:
            key = case_key(stem)
            data = skeleton(key, b, l0=args.l0, verdict=args.verdict)
            if write_truth(key, data, force=args.force) and data["verdict"] == VERDICT_TODO:
                todo.append(key)

    if todo:
        print(f"\n[!] verdict 를 채워야 하는 초안 {len(todo)}개: {', '.join(todo)}")
        print("    verdict 는 코드가 추론하면 채점이 순환논리가 되므로 사람이 정한다.")
        print("    (REVIEW_ME 로 남겨두면 score.py 에서 verdict XX 로 눈에 띈다)")


if __name__ == "__main__":
    main()
