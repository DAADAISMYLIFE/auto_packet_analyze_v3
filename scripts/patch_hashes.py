#!/usr/bin/env python3
"""기존 reports/*.json 에 attach_hashes 를 소급 적용한다 (LLM 재실행 불필요, GPU 0).

run.py 의 attach_hashes 는 실행 시점에만 붙으므로, 그 코드가 들어가기 전에 만든
리포트는 iocs.hashes 가 비어 있다. 이 스크립트는 evidence(output/<name>/) 의
malware-candidate 해시를 읽어 기존 리포트의 iocs.hashes 를 채운다. 모델 안 씀.

사용법:
  python3 scripts/patch_hashes.py                 # reports/ 전체
  python3 scripts/patch_hashes.py <reports_dir>   # 다른 디렉터리
"""
import json
import glob
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "llm"))
from tools import Tools  # noqa: E402

REPORTS = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "reports")


def hashes_for(t):
    """evidence 의 malware-candidate 해시 (ms-pol=정상 GPO 제외). run.py attach_hashes 와 동일."""
    return sorted({f["sha256"] for f in t.get_files().get("malware_candidates", [])
                   if f.get("sha256") and "ms-pol" not in (f.get("mime") or "")})


def main():
    files = sorted(glob.glob(os.path.join(REPORTS, "*.json")))
    if not files:
        print(f"(리포트 없음: {REPORTS})")
        return
    for rp in files:
        name = os.path.splitext(os.path.basename(rp))[0]
        with open(rp, encoding="utf-8") as f:
            rep = json.load(f)
        a = rep.get("analysis")
        if not a:
            print(f"{name}: (무혐의/분석없음 — 스킵)")
            continue
        try:
            t = Tools(name)
        except Exception as e:
            print(f"{name}: evidence 못 읽음 — {e}")
            continue
        before = a.get("iocs", {}).get("hashes", [])
        a.setdefault("iocs", {})["hashes"] = hashes_for(t)
        with open(rp, "w", encoding="utf-8") as f:
            json.dump(rep, f, ensure_ascii=False, indent=2)
        after = a["iocs"]["hashes"]
        print(f"{name}: hashes {len(before)} → {len(after)}  {[h[:12] for h in after]}")


if __name__ == "__main__":
    main()
