#!/usr/bin/env bash
# pcap -> Zeek JSON 로그
# 사용법: ./run_zeek.sh <pcap파일>
# 실행 방식 자동 선택:
#   - 네이티브 zeek 설치돼 있으면 그걸 사용 (Colab 등 docker 없는 환경)
#   - 없으면 docker zeek/zeek:latest 사용 (로컬 기본)
set -euo pipefail

PCAP="${1:?사용법: run_zeek.sh <pcap파일>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PCAP_ABS="$(realpath "$PCAP")"
PCAP_DIR="$(dirname "$PCAP_ABS")"
PCAP_NAME="$(basename "$PCAP_ABS")"
NAME="${PCAP_NAME%.*}"
# OUT_DIR 환경변수로 출력경로 덮어쓰기 가능 (extract_log.sh 가 사용). 없으면 기존 기본값.
OUT="${OUT_DIR:-$ROOT/output/zeek/$NAME}"

# 실행 전 출력 청소 (재실행 시 이전 로그/추출파일 누적 방지)
rm -rf "$OUT"
mkdir -p "$OUT"
echo "[zeek] $PCAP_NAME -> $OUT"

# 공통 인자:
#   community-id-logging  : conn.log에 community_id (Suricata alert와 정확 매칭용)
#   mac-logging           : conn.log에 MAC 주소 (호스트 식별용)
#   hash-all-files        : files.log에 md5/sha1/sha256 (멀웨어 식별용)
#   extract-all-files     : 다운로드된 실제 파일을 extract_files/로 추출(carve)
ZEEK_SCRIPTS="policy/protocols/conn/community-id-logging \
policy/protocols/conn/mac-logging \
policy/frameworks/files/hash-all-files \
policy/frameworks/files/extract-all-files"

if command -v zeek >/dev/null 2>&1; then
  # ── 네이티브 zeek (Colab 등) ──
  echo "[zeek] 네이티브 zeek 사용 ($(zeek --version 2>/dev/null | head -1))"
  if ( cd "$OUT" && zeek -C -r "$PCAP_ABS" LogAscii::use_json=T $ZEEK_SCRIPTS ); then
    OK=1
  else
    OK=0
  fi
elif docker info >/dev/null 2>&1; then
  # ── docker zeek (로컬 기본) ──
  echo "[zeek] docker zeek/zeek:latest 사용"
  # --user : host 유저 권한으로 실행 (root 소유 파일 생성 방지 → 청소 가능)
  if docker run --rm \
    --user "$(id -u):$(id -g)" \
    -v "$PCAP_DIR":/pcap:ro \
    -v "$OUT":/out \
    -w /out \
    zeek/zeek:latest \
    zeek -C -r "/pcap/$PCAP_NAME" LogAscii::use_json=T $ZEEK_SCRIPTS; then
    OK=1
  else
    OK=0
  fi
else
  echo "[zeek] ❌ zeek(네이티브)도 docker도 없음 — 둘 중 하나 설치 필요"
  exit 1
fi

if [ "$OK" = "1" ]; then
  echo "[zeek] 완료. 생성된 로그:"
  ls -1 "$OUT"
else
  echo "[zeek] ❌ 읽기 실패 — 지원 안 하는 캡처 포맷일 수 있음 (빈 출력으로 진행)"
fi
