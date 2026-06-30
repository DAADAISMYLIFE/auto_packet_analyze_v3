#!/usr/bin/env bash
# pcap -> Suricata eve.json (alert 포함)
# 사용법: ./run_suricata.sh <pcap파일>
set -euo pipefail

PCAP="${1:?사용법: run_suricata.sh <pcap파일>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PCAP_ABS="$(realpath "$PCAP")"
PCAP_NAME="$(basename "$PCAP_ABS")"
NAME="${PCAP_NAME%.*}"
# OUT_DIR 환경변수로 출력경로 덮어쓰기 가능 (extract_log.sh 가 사용). 없으면 기존 기본값.
OUT="${OUT_DIR:-$ROOT/output/suricata/$NAME}"

# 실행 전 출력 청소 (eve-log append=yes라 재실행 시 누적 → 숫자 오염 방지)
rm -rf "$OUT"
mkdir -p "$OUT"
echo "[suricata] $PCAP_NAME -> $OUT"

# ET Open 룰을 명시적으로 로드 (포터블 핵심):
#   suricata-update는 룰을 /var/lib/suricata/rules/suricata.rules 에 쓰는데,
#   일부 배포판 기본 설정(Ubuntu apt 등)은 다른 경로(/etc/suricata/rules 스텁)를 봐서
#   런타임에 ET 룰을 안 읽어 alert 0이 됨(Colab에서 실측). -S로 그 파일을 직접 지정.
#   (로컬/Colab 둘 다 이 파일이 있으므로 동일 동작. 없으면 yaml 기본 룰로 폴백.)
RULES="/var/lib/suricata/rules/suricata.rules"
RULE_ARG=""
[ -s "$RULES" ] && RULE_ARG="-S $RULES"

# --set outputs.1.eve-log.community-id=true : Zeek conn.log와 조인할 community_id 활성화
#   (Zeek/Suricata 둘 다 seed=0이라 같은 flow에 동일 해시 → 100% 매칭)
# --set outputs.1.eve-log.append=false : 누적 방지 이중 안전장치 (청소와 별개로)
suricata -r "$PCAP_ABS" -l "$OUT" -k none $RULE_ARG \
  --set outputs.1.eve-log.community-id=true \
  --set outputs.1.eve-log.append=false 2>&1 | tail -1

echo "[suricata] alert 개수:"
grep -c '"event_type":"alert"' "$OUT/eve.json" 2>/dev/null || echo 0
echo "[suricata] 완료 -> $OUT/eve.json"
