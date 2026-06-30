#!/usr/bin/env bash
# pcap 하나를 Suricata + Zeek 으로 한번에 분석
# 사용법: ./extract_log.sh <pcap파일경로>
# 출력:  output/<pcap이름>/suricata/   (eve.json 등)
#        output/<pcap이름>/zeek/       (conn.log 등)
set -euo pipefail

PCAP="${1:?사용법: extract_log.sh <pcap파일경로>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPTS="$ROOT/scripts"

PCAP_ABS="$(realpath "$PCAP")"
PCAP_NAME="$(basename "$PCAP_ABS")"
NAME="${PCAP_NAME%.*}"
BASE="$ROOT/output/$NAME"

echo "════════════════════════════════════════════════════════"
echo "[extract_log] $PCAP_NAME"
echo "             → $BASE/{suricata,zeek}"
echo "════════════════════════════════════════════════════════"

# run_*.sh 가 OUT_DIR 을 보고 그 경로에 출력함 (run_*.sh 가 내부에서 rm -rf + mkdir 처리)
OUT_DIR="$BASE/suricata" bash "$SCRIPTS/run_suricata.sh" "$PCAP_ABS"
OUT_DIR="$BASE/zeek"     bash "$SCRIPTS/run_zeek.sh"     "$PCAP_ABS"

echo
echo "[extract_log] ✅ 완료 — 생성된 트리:"
ls -R "$BASE"

