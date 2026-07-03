#!/usr/bin/env python3
"""Zeek 가 md5 만 뽑고 sha256 을 null 로 둔 경우(예: Colab native zeek 8.0.5)를
carve 된 파일(zeek/extract_files/)에서 직접 sha256 을 계산해 복구한다.

files.log 는 각 파일의 md5 와 carve 파일명(extracted)을 갖고 있으므로,
carve 파일을 sha256 해싱해 md5→sha256 맵을 만들고, evidence.json 의
files[].sha256(=null)을 md5 로 매칭해 채운다. Zeek/Suricata 재실행 불필요, GPU 0.

사용법: python3 scripts/backfill_sha256.py
"""
import glob
import hashlib
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "output")


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def md5_to_sha256(zdir):
    """files.log → {md5: sha256}. sha256 이 이미 있으면 그대로, 없으면 carve 파일에서 계산."""
    fl = os.path.join(zdir, "files.log")
    exdir = os.path.join(zdir, "extract_files")
    m = {}
    if not os.path.exists(fl):
        return m
    for line in open(fl, encoding="utf-8"):
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        md5 = r.get("md5")
        if not md5:
            continue
        if r.get("sha256"):
            m[md5] = r["sha256"]
            continue
        ex = r.get("extracted")
        if ex:
            p = os.path.join(exdir, ex)
            if os.path.exists(p):
                m[md5] = sha256_of(p)
    return m


def main():
    for base in sorted(glob.glob(os.path.join(OUT, "*") + os.sep)):
        ev_path = os.path.join(base, "evidence.json")
        if not os.path.exists(ev_path):
            continue
        m = md5_to_sha256(os.path.join(base, "zeek"))
        ev = json.load(open(ev_path, encoding="utf-8"))
        n = 0
        for f in ev.get("files", []):
            if not f.get("sha256") and f.get("md5") in m:
                f["sha256"] = m[f["md5"]]
                n += 1
        if n:
            with open(ev_path, "w", encoding="utf-8") as fp:
                json.dump(ev, fp, ensure_ascii=False, indent=2)
        name = os.path.basename(base.rstrip(os.sep))
        print(f"{name}: sha256 backfilled = {n}")


if __name__ == "__main__":
    main()
