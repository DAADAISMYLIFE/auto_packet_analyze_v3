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
    """output/<case>/evidence.json 을 훑어 관측된 IP/도메인/해시 집합."""
    path = os.path.join(output_dir, case, "evidence.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        ev = json.load(f)
    ips, doms, hashes = set(), set(), set()

    def walk(o):
        if isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
        elif isinstance(o, str):
            s = o.strip()
            if IP_RE.fullmatch(s):
                ips.add(s.lower())
            elif HASH_RE.fullmatch(s):
                hashes.add(s.lower())
            else:
                for m in DOMAIN_RE.findall(s):
                    doms.add(m.lower())
    walk(ev)
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

    ti = truth.get("iocs", {})
    r["iocR"] = _recall(atoms["ioc_ips"], ti.get("c2", []) + ti.get("delivery", []) + ti.get("exfil", []))
    r["domR"] = _domain_recall(atoms["domains"], ti.get("domains", []))
    r["hashR"] = _recall(atoms["hashes"], ti.get("hashes", []))

    if ev is not None:
        r["ground_bad_ips"] = sorted(ip for ip in atoms["ioc_ips"] if ip not in ev["ips"])
        r["ground_bad_hash"] = sorted(h for h in atoms["hashes"] if h not in ev["hashes"])
        r["ground_bad_dom"] = _ungrounded_domains(atoms["domains"], ev["domains"])
        r["ground_ok"] = not (r["ground_bad_ips"] or r["ground_bad_hash"])
    else:
        r["ground_ok"], r["ground_bad_ips"], r["ground_bad_hash"], r["ground_bad_dom"] = None, [], [], []

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
    hdr = f"{'case':<10} {'verdict':<14} {'grd':<4} {'vR':<5} {'infra!':<7} {'hashR':<6} {'iocR':<5} {'domR':<5} {'pz':<3}"
    print(hdr); print("-" * len(hdr))
    agg = {}
    for case, r in rows:
        if r is None:
            print(f"{case:<10} (truth 없음 — 스킵)"); continue
        vok = "OK" if r["verdict_ok"] else "XX"
        grd = "-" if r["ground_ok"] is None else ("ok" if r["ground_ok"] else "BAD")
        infra = "ok" if not r["infra_bad"] else f"FAIL{len(r['infra_bad'])}"
        pz = "-" if r["pz_ok"] is None else ("OK" if r["pz_ok"] else "XX")
        print(f"{case:<10} {(str(r['verdict'])+'/'+vok):<14} {grd:<4} {_f(r['victimR']):<5} "
              f"{infra:<7} {_f(r['hashR']):<6} {_f(r['iocR']):<5} {_f(r['domR']):<5} {pz:<3}")
        for k in ("victimR", "iocR", "domR", "hashR"):
            if r[k] is not None:
                agg.setdefault(k, []).append(r[k])
        agg.setdefault("verdict", []).append(1 if r["verdict_ok"] else 0)
        agg.setdefault("infra_fail", []).append(1 if r["infra_bad"] else 0)
        if r["ground_ok"] is not None:
            agg.setdefault("ground_fail", []).append(0 if r["ground_ok"] else 1)
    if agg:
        m = lambda k: sum(agg[k]) / len(agg[k]) if agg.get(k) else float("nan")
        print("-" * len(hdr))
        print(f"{'AGG':<10} verdict={m('verdict'):.2f}  victimR={m('victimR'):.2f}  iocR={m('iocR'):.2f}  "
              f"domR={m('domR'):.2f}  hashR={m('hashR'):.2f}  "
              f"infra_fail={sum(agg.get('infra_fail', []))}  ground_fail={sum(agg.get('ground_fail', []))}")
    for case, r in rows:
        if r and (r["ground_bad_ips"] or r["ground_bad_hash"] or r["infra_bad"]):
            det = []
            if r["ground_bad_ips"]:  det.append(f"환각IP={r['ground_bad_ips']}")
            if r["ground_bad_hash"]: det.append(f"환각HASH={len(r['ground_bad_hash'])}")
            if r["infra_bad"]:       det.append(f"infra피해자오인={r['infra_bad']}")
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
