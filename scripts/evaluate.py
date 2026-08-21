#!/usr/bin/env python3
"""재현 가능한 반복 평가 루프.

각 모델/seed/case를 독립 실행하고 report, stdout/stderr, 시간, 설정, 점수를 실험
디렉터리에 보존한다. 최신 reports/*.json 덮어쓰기와 무관하게 이전 실행을 비교할 수 있다.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
from score import score_file


def slug(value):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value)


def available_cases():
    out = os.path.join(ROOT, "output")
    if not os.path.isdir(out):
        return []
    return sorted(name for name in os.listdir(out)
                  if os.path.isfile(os.path.join(out, name, "evidence.json")))


def env_default(key, fallback):
    path = os.path.join(ROOT, ".env")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                if line.startswith(key + "="):
                    return line.split("=", 1)[1].strip()
    return fallback


def command_text(command):
    try:
        return subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def sha256_file(path):
    if not os.path.isfile(path):
        return None
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", nargs="+", default=None)
    parser.add_argument("--models", nargs="+", default=None)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seed-start", type=int, default=42)
    parser.add_argument("--no-llm", action="store_true")
    parser.add_argument("--max-context-chars", type=int, default=48000)
    parser.add_argument("--experiments", default=os.path.join(ROOT, "experiments"))
    args = parser.parse_args()

    cases = args.cases or available_cases()
    models = args.models or [env_default("MODEL", "gemma4:26b")]
    if not cases:
        raise SystemExit("evidence.json이 있는 output/<case>가 없습니다")
    if args.repeats < 1:
        raise SystemExit("--repeats는 1 이상이어야 합니다")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    exp_dir = os.path.join(args.experiments, stamp)
    os.makedirs(exp_dir, exist_ok=False)
    manifest = {
        "created_utc": stamp, "cases": cases, "models": models,
        "repeats": args.repeats, "no_llm": args.no_llm,
        "max_context_chars": args.max_context_chars, "runs": [],
        "provenance": {
            "git_commit": command_text(["git", "rev-parse", "HEAD"]),
            "git_diff_sha256": hashlib.sha256(command_text(["git", "diff", "--binary"]).encode()).hexdigest(),
            "suricata": command_text(["suricata", "-V"]),
            "zeek": command_text(["zeek", "--version"]),
            "ollama": command_text(["ollama", "--version"]),
            "suricata_rules_sha256": sha256_file("/var/lib/suricata/rules/suricata.rules"),
        },
    }

    for model in models:
        for repeat in range(args.repeats):
            seed = args.seed_start + repeat
            report_dir = os.path.join(exp_dir, slug(model), f"seed-{seed}")
            os.makedirs(report_dir, exist_ok=True)
            for case in cases:
                env = os.environ.copy()
                env.update({"MODEL": model, "SEED": str(seed),
                            "CONTEXT_MAX_CHARS": str(args.max_context_chars)})
                cmd = [sys.executable, os.path.join(ROOT, "llm", "run.py"), case,
                       "--max-context-chars", str(args.max_context_chars)]
                if args.no_llm:
                    cmd.append("--no-llm")
                started = time.monotonic()
                proc = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
                elapsed = round(time.monotonic() - started, 3)
                record = {"model": model, "seed": seed, "case": case,
                          "returncode": proc.returncode, "wall_seconds": elapsed,
                          "evidence_sha256": sha256_file(os.path.join(ROOT, "output", case, "evidence.json"))}
                log_path = os.path.join(report_dir, f"{case}.log")
                with open(log_path, "w", encoding="utf-8") as handle:
                    handle.write(proc.stdout)
                    if proc.stderr:
                        handle.write("\n[stderr]\n" + proc.stderr)
                source = os.path.join(ROOT, "reports", f"{case}.json")
                target = os.path.join(report_dir, f"{case}.json")
                if proc.returncode == 0 and os.path.exists(source):
                    shutil.copy2(source, target)
                    _, result = score_file(target, os.path.join(ROOT, "answers", "truth"),
                                           os.path.join(ROOT, "output"))
                    record["score"] = result
                manifest["runs"].append(record)
                print(f"[{model} seed={seed}] {case}: rc={proc.returncode} {elapsed}s")

    with open(os.path.join(exp_dir, "manifest.json"), "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, ensure_ascii=False, indent=2)
    print(f"[experiment] {exp_dir}")


if __name__ == "__main__":
    main()
