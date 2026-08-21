#!/usr/bin/env python3
"""보고서 평가: recall뿐 아니라 precision/F1, 의미 bucket, 오탐을 함께 측정한다."""
import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def case_of(path):
    stem = os.path.splitext(os.path.basename(path))[0]
    digits = re.sub(r"\D", "", stem)
    return digits[:8] if len(digits) >= 8 else stem


def norm_set(values):
    return {str(x).strip().lower() for x in values or [] if x is not None and str(x).strip()}


def domain_match(a, b):
    a, b = str(a).lower(), str(b).lower()
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def evidence_iocs(case, output_dir):
    path = os.path.join(output_dir, case, "evidence.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as handle:
        ev = json.load(handle)
    ext = ev.get("external") or {}
    internal = {str(h.get("ip")).lower() for h in ev.get("hosts", []) if h.get("ip")}
    ips, domains, hashes = set(), set(), set()
    for row in ext.get("ips", []) or []:
        if row.get("ip"):
            ips.add(str(row["ip"]).lower())
    for row in ext.get("domains", []) or []:
        if row.get("query"):
            domains.add(str(row["query"]).lower())
        for answer in row.get("answers", []) or []:
            if IP_RE.fullmatch(str(answer)):
                ips.add(str(answer).lower())
    for row in ext.get("sni", []) or []:
        if row.get("sni"):
            domains.add(str(row["sni"]).lower())
    # 인바운드 공격자는 external.ips(아웃바운드 집계)에 없고 alert에만 존재할 수 있다.
    for alert in ev.get("alerts", []) or []:
        for ip in (alert.get("src_ips") or []) + (alert.get("dst_ips") or []):
            value = str(ip).lower()
            if value not in internal and IP_RE.fullmatch(value):
                ips.add(value)
    for row in ev.get("files", []) or []:
        for key in ("sha256", "md5"):
            if row.get(key):
                hashes.add(str(row[key]).lower())
    return {"ips": ips, "domains": domains, "hashes": hashes}


def load_atoms(path):
    with open(path, encoding="utf-8") as handle:
        report = json.load(handle)
    analysis = report.get("analysis") or {}
    statuses = {str(v.get("ip")).strip().lower(): str(v.get("status") or "").lower()
                for v in analysis.get("victims", []) if v.get("ip")}
    iocs = analysis.get("iocs") or {}
    buckets = {key: norm_set(iocs.get(key, [])) for key in
               ("c2", "delivery", "exfil", "domains", "hashes")}
    attackers = norm_set(analysis.get("attackers", []))
    return {
        "verdict": report.get("verdict"), "victim_status": statuses,
        "victims": {ip for ip, status in statuses.items() if status == "compromised"},
        "buckets": buckets, "attackers": attackers,
        "ioc_ips": buckets["c2"] | buckets["delivery"] | buckets["exfil"] | attackers,
        "domains": buckets["domains"], "hashes": buckets["hashes"],
        "patient_zero": str(analysis.get("patient_zero") or "").strip().lower() or None,
        "techniques": norm_set(a.get("technique") for a in analysis.get("attacks", [])),
        "dispositions": {str(a.get("id") or f"{a.get('actor')}->{a.get('target')}:{a.get('technique')}"):
                         a.get("disposition") for a in analysis.get("attacks", [])},
        "run": report.get("_run") or {},
    }


def prf(found, truth, matcher=None):
    found, truth = set(found), set(truth)
    if matcher:
        tp_truth = {t for t in truth if any(matcher(f, t) for f in found)}
        tp_found = {f for f in found if any(matcher(f, t) for t in truth)}
        tp_for_p, tp_for_r = len(tp_found), len(tp_truth)
    else:
        tp_for_p = tp_for_r = len(found & truth)
    precision = tp_for_p / len(found) if found else (1.0 if not truth else 0.0)
    recall = tp_for_r / len(truth) if truth else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1,
            "fp": sorted(found - truth) if not matcher else
                  sorted(f for f in found if not any(matcher(f, t) for t in truth)),
            "fn": sorted(truth - found) if not matcher else
                  sorted(t for t in truth if not any(matcher(f, t) for f in found))}


def score(atoms, truth, observed):
    truth_victims = norm_set(v.get("ip") for v in truth.get("victims", []))
    ti = truth.get("iocs") or {}
    truth_buckets = {key: norm_set(ti.get(key, [])) for key in
                     ("c2", "delivery", "exfil", "domains", "hashes")}
    truth_ioc_ips = truth_buckets["c2"] | truth_buckets["delivery"] | truth_buckets["exfil"]
    # 기존 truth가 인바운드 공격자를 c2에 넣은 경우도 aggregate 탐지 성능에서는 인정하되,
    # 새 truth의 attackers 필드가 생기면 별도 의미 지표로 평가한다.
    truth_attackers = norm_set(truth.get("attackers", []))
    truth_ioc_all = truth_ioc_ips | truth_attackers

    result = {
        "verdict": atoms["verdict"], "verdict_ok": atoms["verdict"] == truth.get("verdict"),
        "victim": prf(atoms["victims"], truth_victims),
        "ioc_ip": prf(atoms["ioc_ips"], truth_ioc_all),
        "domain": prf(atoms["domains"], truth_buckets["domains"], domain_match),
        "hash": prf(atoms["hashes"], truth_buckets["hashes"]),
        "bucket": {}, "run": atoms["run"],
    }
    for key in ("c2", "delivery", "exfil"):
        result["bucket"][key] = prf(atoms["buckets"][key], truth_buckets[key])
    if "attackers" in truth:
        result["bucket"]["attackers"] = prf(atoms["attackers"], truth_attackers)

    infra = norm_set(truth.get("infra_ips", []))
    result["infra_bad"] = sorted(ip for ip, status in atoms["victim_status"].items()
                                 if ip in infra and status == "compromised")
    result["unexpected_compromised"] = sorted(atoms["victims"] - truth_victims)
    explicit_benign = norm_set(truth.get("benign_ips", [])) | norm_set(truth.get("benign_hashes", []))
    result["explicit_benign_fp"] = sorted((atoms["ioc_ips"] | atoms["hashes"]) & explicit_benign)

    if observed is None:
        result["ground_ok"], result["ungrounded"] = None, []
    else:
        bad = ([f"ip:{x}" for x in atoms["ioc_ips"] if x not in observed["ips"]] +
               [f"hash:{x}" for x in atoms["hashes"] if x not in observed["hashes"]] +
               [f"domain:{x}" for x in atoms["domains"]
                if not any(domain_match(x, e) for e in observed["domains"])])
        result["ungrounded"] = sorted(bad)
        result["ground_ok"] = not bad

    patient_zero = truth.get("patient_zero")
    result["patient_zero_ok"] = (atoms["patient_zero"] == str(patient_zero).lower()) \
        if patient_zero else None

    truth_techniques = norm_set(truth.get("techniques", []))
    if truth_techniques:
        def technique_match(found, expected):
            a = re.sub(r"[^a-z0-9]+", " ", found.lower())
            b = re.sub(r"[^a-z0-9]+", " ", expected.lower())
            tokens = {x for x in a.split() if len(x) >= 4}
            return bool(tokens & {x for x in b.split() if len(x) >= 4})
        result["technique"] = prf(atoms["techniques"], truth_techniques, technique_match)
    else:
        result["technique"] = None
    return result


def score_file(path, truth_dir, output_dir):
    key, stem = case_of(path), os.path.splitext(os.path.basename(path))[0]
    truth_path = os.path.join(truth_dir, key + ".json")
    if not os.path.exists(truth_path):
        return key, None
    with open(truth_path, encoding="utf-8") as handle:
        truth = json.load(handle)
    observed = evidence_iocs(stem, output_dir) or evidence_iocs(key, output_dir)
    return key, score(load_atoms(path), truth, observed)


def collect(path, truth_dir, output_dir):
    files = sorted(os.path.join(path, f) for f in os.listdir(path) if f.endswith(".json")) \
        if os.path.isdir(path) else [path]
    return [score_file(item, truth_dir, output_dir) for item in files]


def _pct(value):
    return f"{value:.2f}"


def print_rows(rows, label):
    print(f"\n=== {label} ===")
    print(f"{'case':<12} {'verdict':<14} {'vF1':<5} {'iF1':<5} {'dF1':<5} {'hF1':<5} {'ground':<7} {'FP':<4} {'pz':<3}")
    valid = []
    for case, result in rows:
        if result is None:
            print(f"{case:<12} truth 없음")
            continue
        valid.append(result)
        fp = (len(result["victim"]["fp"]) + len(result["ioc_ip"]["fp"]) +
              len(result["domain"]["fp"]) + len(result["hash"]["fp"]) +
              len(result["explicit_benign_fp"]))
        ground = "-" if result["ground_ok"] is None else ("ok" if result["ground_ok"] else "BAD")
        pz = "-" if result["patient_zero_ok"] is None else ("OK" if result["patient_zero_ok"] else "XX")
        verdict = f"{result['verdict']}/" + ("OK" if result["verdict_ok"] else "XX")
        print(f"{case:<12} {verdict:<14} {_pct(result['victim']['f1']):<5} "
              f"{_pct(result['ioc_ip']['f1']):<5} {_pct(result['domain']['f1']):<5} "
              f"{_pct(result['hash']['f1']):<5} {ground:<7} {fp:<4} {pz:<3}")
        if fp or result["infra_bad"] or result["ungrounded"]:
            print(f"  ! victimFP={result['victim']['fp']} iocFP={result['ioc_ip']['fp']} "
                  f"domainFP={result['domain']['fp']} infra={result['infra_bad']} "
                  f"ungrounded={result['ungrounded']}")
    if valid:
        mean = lambda expr: sum(expr(r) for r in valid) / len(valid)
        print("-" * 76)
        print(f"macro verdict={mean(lambda r: float(r['verdict_ok'])):.2f} "
              f"victimF1={mean(lambda r: r['victim']['f1']):.2f} "
              f"iocF1={mean(lambda r: r['ioc_ip']['f1']):.2f} "
              f"domainF1={mean(lambda r: r['domain']['f1']):.2f} "
              f"hashF1={mean(lambda r: r['hash']['f1']):.2f}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", nargs="?", help="reports 파일 또는 디렉터리")
    parser.add_argument("--compare", nargs=2, metavar=("A", "B"))
    parser.add_argument("--truth", default=os.path.join(ROOT, "answers", "truth"))
    parser.add_argument("--output", default=os.path.join(ROOT, "output"))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    def resolve(value):
        return value if os.path.isabs(value) else os.path.join(ROOT, value)

    groups = [(path, collect(resolve(path), args.truth, args.output)) for path in args.compare] \
        if args.compare else ([(args.target, collect(resolve(args.target), args.truth, args.output))]
                              if args.target else [])
    if not groups:
        parser.print_help()
        raise SystemExit(1)
    if args.json:
        print(json.dumps({label: dict(rows) for label, rows in groups}, ensure_ascii=False, indent=2))
    else:
        for label, rows in groups:
            print_rows(rows, os.path.basename(label.rstrip("/")))


if __name__ == "__main__":
    main()
