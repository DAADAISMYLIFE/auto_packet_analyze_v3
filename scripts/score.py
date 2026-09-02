#!/usr/bin/env python3
"""
채점 — run.py 가 뽑은 reports/<case>.json 을 정답(truth)과 비교해 숫자로 낸다.

입력은 JSON 만. (run.py 는 이미 REPORT_SCHEMA JSON 을 뱉으므로 산문 파싱 없음.)

지표
  verdict : truth.verdict 일치?
  ground  : 보고서 IOC 가 전부 evidence.json 안에 있나 (환각/오염 탐지, 정답 불필요)
  victimR : truth 피해자 IP recall
  infra!  : truth.infra_ips 를 status=compromised 로 부른 건수 (0이어야 정상; #1)
  hashR   : truth 해시 recall (#6)
  iocR    : truth C2/delivery/exfil IP recall
  domR    : truth 도메인 recall (suffix 매칭)
  pz      : patient_zero 일치

사용법
  python scripts/score.py reports                    # 디렉터리 전체
  python scripts/score.py reports/20210616.json      # 파일 하나
  python scripts/score.py --compare reports_a reports_b
"""
import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
HASH_RE = re.compile(r"[0-9a-fA-F]{64}|[0-9a-fA-F]{32}")
DOMAIN_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}", re.I)


def case_of(path):
    stem = os.path.splitext(os.path.basename(path))[0]
    digits = re.sub(r"\D", "", stem)
    return digits[:8] if len(digits) >= 8 else stem


def norm_set(xs):
    return {str(x).strip().lower() for x in xs if x is not None and str(x).strip()}


# ─────────────────────────── evidence (grounding) ───────────────────────────
def evidence_iocs(case, output_dir):
    """output/<case>/evidence.json 의 '관측된 IOC' 집합 (grounding 기준).

    전체 트리 정규식 walk 는 내부호스트·유저명·파일명까지 grounded 로 오인하므로
    build_evidence 가 만든 구조화 필드만 읽는다:
      external.ips[].ip + domains[].answers  →  관측된 IP
      external.domains[].query + sni[].sni    →  관측된 도메인/SNI
      files[].sha256 / .md5                    →  관측된 파일 해시
    """
    path = os.path.join(output_dir, case, "evidence.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        ev = json.load(f)
    ext = ev.get("external", {}) or {}
    ips, doms, hashes = set(), set(), set()
    for x in ext.get("ips", []) or []:
        if x.get("ip"):
            ips.add(str(x["ip"]).lower())
    for d in ext.get("domains", []) or []:
        if d.get("query"):
            doms.add(str(d["query"]).lower())
        for a in (d.get("answers") or []):
            if a:
                ips.add(str(a).lower())
    for s in ext.get("sni", []) or []:
        if s.get("sni"):
            doms.add(str(s["sni"]).lower())
    for frec in ev.get("files", []) or []:
        for k in ("sha256", "md5"):
            if frec.get(k):
                hashes.add(str(frec[k]).lower())
    # 위협 alert 의 외부 IP — 인바운드 공격자는 external.ips(아웃바운드 dst 집계)에 없고
    #   alert src 로만 존재한다. run.py 승격기가 이 근거로 넣은 IP 를 grounding 이
    #   '환각'으로 오판하던 버그(q2 실측: 146.52.78.242 등 5개) 수정.
    internal = {str(h.get("ip")).lower() for h in ev.get("hosts", []) if h.get("ip")}
    for a in ev.get("alerts", []) or []:
        if (a.get("threat_class") or "") in ("threat", "rat"):
            for ip in (a.get("src_ips") or []) + (a.get("dst_ips") or []):
                v = str(ip).lower()
                if v and v not in internal and IP_RE.fullmatch(v):
                    ips.add(v)
    # http Host 헤더 도메인 — DNS 무질의 직결 C2/TDS (tools.observed_iocs 와 동일 근거,
    #   q2 실측: searchl.org / 0a0a.eu 를 환각도메인으로 오판하던 버그)
    for h in (ext.get("http") or []):
        host = str(h.get("url") or "").split("/", 1)[0].lower().split(":", 1)[0]
        if host and "." in host and not IP_RE.fullmatch(host):
            doms.add(host)
    return {"ips": ips, "domains": doms, "hashes": hashes}


# ─────────────────────────── report → atoms ───────────────────────────
def load_atoms(path):
    with open(path, encoding="utf-8") as f:
        rep = json.load(f)
    a = rep.get("analysis") or {}
    victim_status = {(v.get("ip") or "").strip().lower(): (v.get("status") or "").lower()
                     for v in a.get("victims", []) if v.get("ip")}
    iocs = a.get("iocs", {})
    return {
        "verdict": rep.get("verdict"),
        "victim_status": victim_status,
        "victims": {ip for ip, st in victim_status.items() if st == "compromised"},
        "ioc_ips": norm_set(iocs.get("c2", []) + iocs.get("delivery", []) + iocs.get("exfil", [])),
        "domains": norm_set(iocs.get("domains", [])),
        "hashes": norm_set(iocs.get("hashes", [])),
        "patient_zero": (a.get("patient_zero") or "").strip().lower() or None,
    }


# ─────────────────────────── scoring ───────────────────────────
def _recall(found, truth):
    truth = norm_set(truth)
    if not truth:
        return None
    return len({t for t in truth if t in found}) / len(truth)


def _domain_recall(found, truth):
    truth = norm_set(truth)
    if not truth:
        return None
    hit = sum(1 for t in truth
              if any(d == t or d.endswith("." + t) or t.endswith("." + d) for d in found))
    return hit / len(truth)


def _precision(found, truth):
    """보고한 것 중 truth 에 있는 비율. found 비면 None (보고 안 함 ≠ 정확).
    truth 가 비었는데 보고했으면 0.0 — '없는 걸 만들어냄'은 최악의 precision."""
    found = set(found)
    if not found:
        return None
    truth = norm_set(truth)
    return len([f for f in found if f in truth]) / len(found)


def _domain_precision(found, truth):
    found = set(found)
    if not found:
        return None
    truth = norm_set(truth)
    hit = sum(1 for d in found
              if any(d == t or d.endswith("." + t) or t.endswith("." + d) for t in truth))
    return hit / len(found)


def _ungrounded_domains(found, ev):
    return [d for d in found
            if not any(d == e or d.endswith("." + e) or e.endswith("." + d) for e in ev)]


def score(atoms, truth, ev):
    r = {"verdict": atoms["verdict"],
         "verdict_ok": atoms["verdict"] == truth.get("verdict")}

    r["victimR"] = _recall(atoms["victims"], [v["ip"] for v in truth.get("victims", [])])

    infra = norm_set(truth.get("infra_ips", []))
    r["infra_bad"] = sorted(ip for ip, st in atoms["victim_status"].items()
                            if ip in infra and st == "compromised")

    # victim precision: compromised 라고 부른 것 중 truth 피해자 비율 (초과 = 격리 오폭 후보)
    truth_victims = norm_set(v["ip"] for v in truth.get("victims", []))
    r["victimP"] = _precision(atoms["victims"], truth_victims)
    r["over_victims"] = sorted(atoms["victims"] - truth_victims)

    ti = truth.get("iocs", {})
    truth_ips = norm_set(ti.get("c2", []) + ti.get("delivery", []) + ti.get("exfil", []))
    truth_doms = norm_set(ti.get("domains", []))
    r["iocR"] = _recall(atoms["ioc_ips"], truth_ips)
    r["domR"] = _domain_recall(atoms["domains"], ti.get("domains", []))
    r["hashR"] = _recall(atoms["hashes"], ti.get("hashes", []))
    # ── precision (판결문 P0-1): drop 룰을 뽑는 시스템의 1급 지표 — '뭘 잘못 올렸나' ──
    #   주의: truth IOC 목록의 완전성에 의존한다(공식답안 케이스는 준수, 자체라벨은 근사).
    #   초과분은 '환각'이 아니라 'truth 밖'(진짜 신규 발견일 수도) — 목록을 보고 사람이 판단.
    r["iocP"] = _precision(atoms["ioc_ips"], truth_ips)
    r["domP"] = _domain_precision(atoms["domains"], truth_doms)
    r["hashP"] = _precision(atoms["hashes"], norm_set(ti.get("hashes", [])))
    r["over_ips"] = sorted(ip for ip in atoms["ioc_ips"] if ip not in truth_ips)
    r["over_doms"] = sorted(d for d in atoms["domains"]
                            if not any(d == t or d.endswith("." + t) or t.endswith("." + d)
                                       for t in truth_doms))

    if ev is not None:
        r["ground_bad_ips"] = sorted(ip for ip in atoms["ioc_ips"] if ip not in ev["ips"])
        r["ground_bad_hash"] = sorted(h for h in atoms["hashes"] if h not in ev["hashes"])
        r["ground_bad_dom"] = _ungrounded_domains(atoms["domains"], ev["domains"])
        r["ground_ok"] = not (r["ground_bad_ips"] or r["ground_bad_hash"] or r["ground_bad_dom"])
    else:
        r["ground_ok"], r["ground_bad_ips"], r["ground_bad_hash"], r["ground_bad_dom"] = None, [], [], []

    # false-positive: 보고서가 '정상인데 악성으로 올린' IOC (truth.benign_*)
    #   grounding·recall 로는 안 잡힘 — WU 업데이트 해시를 iocs 에 넣는 오탐을 여기서 잡는다
    benign_h = norm_set(truth.get("benign_hashes", []))
    benign_i = norm_set(truth.get("benign_ips", []))
    r["fp"] = (sorted(h for h in atoms["hashes"] if h in benign_h)
               + sorted(ip for ip in atoms["ioc_ips"] if ip in benign_i))

    pz = truth.get("patient_zero")
    r["pz_ok"] = (atoms["patient_zero"] == str(pz).lower()) if pz else None
    return r


# ─────────────────────────── driver ───────────────────────────
def score_file(path, truth_dir, output_dir):
    key = case_of(path)                                       # truth 키 (8자리 날짜 또는 stem)
    stem = os.path.splitext(os.path.basename(path))[0]        # evidence 디렉터리명 (= pcap stem)
    tpath = os.path.join(truth_dir, key + ".json")
    if not os.path.exists(tpath):
        return key, None
    with open(tpath, encoding="utf-8") as f:
        truth = json.load(f)
    # evidence 디렉터리는 stem 우선, 없으면 8자리 키로 폴백 (로컬/Kaggle 명명 차이 흡수)
    ev = evidence_iocs(stem, output_dir) or evidence_iocs(key, output_dir)
    return key, score(load_atoms(path), truth, ev)


def _f(x):
    return "  - " if x is None else f"{x:.2f}"


def print_rows(rows, label):
    print(f"\n=== {label} ===")
    hdr = (f"{'case':<10} {'verdict':<14} {'grd':<4} {'vR':<5} {'vP':<5} {'infra!':<7} "
           f"{'iocR':<5} {'iocP':<5} {'domR':<5} {'domP':<5} {'hashR':<6} {'fp':<4} {'pz':<3}")
    print(hdr); print("-" * len(hdr))
    agg = {}
    for case, r in rows:
        if r is None:
            print(f"{case:<10} (truth 없음 — 스킵)"); continue
        vok = "OK" if r["verdict_ok"] else "XX"
        grd = "-" if r["ground_ok"] is None else ("ok" if r["ground_ok"] else "BAD")
        infra = "ok" if not r["infra_bad"] else f"FAIL{len(r['infra_bad'])}"
        fp = "ok" if not r["fp"] else f"FP{len(r['fp'])}"
        pz = "-" if r["pz_ok"] is None else ("OK" if r["pz_ok"] else "XX")
        print(f"{case:<10} {(str(r['verdict'])+'/'+vok):<14} {grd:<4} {_f(r['victimR']):<5} "
              f"{_f(r['victimP']):<5} {infra:<7} {_f(r['iocR']):<5} {_f(r['iocP']):<5} "
              f"{_f(r['domR']):<5} {_f(r['domP']):<5} {_f(r['hashR']):<6} {fp:<4} {pz:<3}")
        for k in ("victimR", "victimP", "iocR", "iocP", "domR", "domP", "hashR"):
            if r[k] is not None:
                agg.setdefault(k, []).append(r[k])
        agg.setdefault("verdict", []).append(1 if r["verdict_ok"] else 0)
        agg.setdefault("infra_fail", []).append(1 if r["infra_bad"] else 0)
        agg.setdefault("fp_total", []).append(len(r["fp"]))
        if r["ground_ok"] is not None:
            agg.setdefault("ground_fail", []).append(0 if r["ground_ok"] else 1)
    if agg:
        m = lambda k: sum(agg[k]) / len(agg[k]) if agg.get(k) else float("nan")
        print("-" * len(hdr))
        print(f"{'AGG':<10} verdict={m('verdict'):.2f}  victim R/P={m('victimR'):.2f}/{m('victimP'):.2f}  "
              f"ioc R/P={m('iocR'):.2f}/{m('iocP'):.2f}  dom R/P={m('domR'):.2f}/{m('domP'):.2f}  "
              f"hashR={m('hashR'):.2f}  "
              f"infra_fail={sum(agg.get('infra_fail', []))}  ground_fail={sum(agg.get('ground_fail', []))}  "
              f"fp_total={sum(agg.get('fp_total', []))}")
    for case, r in rows:
        if r and (r["ground_bad_ips"] or r["ground_bad_hash"] or r["ground_bad_dom"] or r["infra_bad"]
                  or r["fp"] or r.get("over_ips") or r.get("over_doms") or r.get("over_victims")):
            det = []
            if r.get("over_victims"): det.append(f"초과피해자={r['over_victims']}")
            if r.get("over_ips"):     det.append(f"truth밖IP={r['over_ips'][:8]}")
            if r.get("over_doms"):    det.append(f"truth밖도메인={r['over_doms'][:8]}")
            if r["ground_bad_ips"]:  det.append(f"환각IP={r['ground_bad_ips']}")
            if r["ground_bad_hash"]: det.append(f"환각HASH={len(r['ground_bad_hash'])}")
            if r["ground_bad_dom"]:  det.append(f"환각도메인={r['ground_bad_dom']}")
            if r["infra_bad"]:       det.append(f"infra피해자오인={r['infra_bad']}")
            if r["fp"]:              det.append(f"오탐(정상을악성으로)={[x[:10] for x in r['fp']]}")
            print(f"  ! {case}: {'  '.join(det)}")


def collect(path, truth_dir, output_dir):
    if os.path.isdir(path):
        files = sorted(os.path.join(path, f) for f in os.listdir(path) if f.endswith(".json"))
    else:
        files = [path]
    return [score_file(fp, truth_dir, output_dir) for fp in files]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", help="reports 파일 또는 디렉터리")
    ap.add_argument("--compare", nargs=2, metavar=("A", "B"))
    ap.add_argument("--truth", default=os.path.join(ROOT, "answers", "truth"))
    ap.add_argument("--output", default=os.path.join(ROOT, "output"))
    args = ap.parse_args()

    def resolve(d):
        return d if os.path.isabs(d) else os.path.join(ROOT, d)

    if args.compare:
        for d in args.compare:
            dd = resolve(d)
            print_rows(collect(dd, args.truth, args.output), os.path.basename(dd.rstrip("/")))
    elif args.target:
        t = resolve(args.target)
        print_rows(collect(t, args.truth, args.output), os.path.basename(t.rstrip("/")))
    else:
        ap.print_help(); sys.exit(1)


if __name__ == "__main__":
    main()
