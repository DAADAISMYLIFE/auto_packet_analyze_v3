#!/usr/bin/env bash
# =============================================================================
# auto_packet_analyze_v3 setup
#   1) Suricata + ET Open 룰 (scripts/run_suricata.sh 용)
#   2) Zeek                  (scripts/run_zeek.sh 용)
#   3) Ollama 런타임
#   4) LLM 모델 pull
#   5) llm/test.py 로 응답 확인
#
# 사용법:  ./setup.sh
#   - sudo 권한 필요(apt 설치). 중간에 비밀번호를 물어볼 수 있음.
#   - 여러 번 실행해도 안전(idempotent).
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
VENV="$ROOT/venv"
MODEL="${MODEL:-gemma4:26b}"   # 일단 gemma4:26b로 명시 (MODEL 환경변수로 덮어쓰기 가능)
UBU_CODENAME="$(. /etc/os-release && echo "${VERSION_ID}")"

log()  { echo -e "\n\033[1;36m[setup]\033[0m $*"; }
ok()   { echo -e "\033[1;32m  ✓\033[0m $*"; }
warn() { echo -e "\033[1;33m  ! \033[0m$*"; }

# sudo 헬퍼: root면 그냥 실행, 아니면 sudo
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi

# -----------------------------------------------------------------------------
log "0/5  apt 갱신"
$SUDO apt-get update -y
$SUDO apt-get install -y curl gnupg ca-certificates lsb-release software-properties-common
$SUDO apt-get install -y zstd

# -----------------------------------------------------------------------------
# 1) Suricata + 룰
# -----------------------------------------------------------------------------
log "1/5  Suricata 설치 + 룰 업데이트"
if ! command -v suricata >/dev/null 2>&1; then
  $SUDO add-apt-repository -y ppa:oisf/suricata-stable || true
  $SUDO apt-get update -y
  $SUDO apt-get install -y suricata
else
  ok "suricata 이미 설치됨 ($(suricata -V 2>/dev/null | head -1))"
fi

# ET Open 룰을 /var/lib/suricata/rules/suricata.rules 에 채움
#   (run_suricata.sh 가 -S 로 이 파일을 직접 로드해서 alert를 받음)
if command -v suricata-update >/dev/null 2>&1; then
  $SUDO suricata-update --no-test || warn "suricata-update 실패(네트워크?) — yaml 기본 룰로 폴백"
else
  warn "suricata-update 없음 — 룰 자동 갱신 건너뜀"
fi
[ -s /var/lib/suricata/rules/suricata.rules ] \
  && ok "룰 파일 준비됨: /var/lib/suricata/rules/suricata.rules" \
  || warn "룰 파일 없음 — run_suricata.sh 가 yaml 기본 룰로 동작함"

# -----------------------------------------------------------------------------
# 2) Zeek
# -----------------------------------------------------------------------------
log "2/5  Zeek 설치"
if command -v zeek >/dev/null 2>&1; then
  ok "zeek 이미 설치됨 ($(zeek --version 2>/dev/null | head -1))"
else
  # 공식 OpenSUSE OBS 저장소 (Ubuntu 22.04 → xUbuntu_22.04)
  REPO="https://download.opensuse.org/repositories/security:/zeek/xUbuntu_${UBU_CODENAME}"
  $SUDO mkdir -p /etc/apt/keyrings
  curl -fsSL "${REPO}/Release.key" \
    | gpg --dearmor \
    | $SUDO tee /etc/apt/keyrings/zeek.gpg >/dev/null
  echo "deb [signed-by=/etc/apt/keyrings/zeek.gpg] ${REPO}/ /" \
    | $SUDO tee /etc/apt/sources.list.d/security-zeek.list >/dev/null
  $SUDO apt-get update -y
  $SUDO apt-get install -y zeek

  # zeek 는 /opt/zeek/bin 에 설치됨 → PATH 에 노출 (run_zeek.sh 의 command -v zeek 용)
  if [ -x /opt/zeek/bin/zeek ] && ! command -v zeek >/dev/null 2>&1; then
    $SUDO ln -sf /opt/zeek/bin/zeek     /usr/local/bin/zeek
    $SUDO ln -sf /opt/zeek/bin/zeek-cut /usr/local/bin/zeek-cut 2>/dev/null || true
  fi
  command -v zeek >/dev/null 2>&1 \
    && ok "zeek 설치 완료 ($(zeek --version 2>/dev/null | head -1))" \
    || warn "zeek 가 PATH 에 없음 — /opt/zeek/bin 을 PATH 에 추가하세요"
fi

# -----------------------------------------------------------------------------
# 3) Ollama
# -----------------------------------------------------------------------------
log "3/5  Ollama 설치"
if command -v ollama >/dev/null 2>&1; then
  ok "ollama 이미 설치됨 ($(ollama --version 2>/dev/null | head -1))"
else
  curl -fsSL https://ollama.com/install.sh | sh
fi

# ollama 서버 기동 확인 (WSL 등 systemd 없는 환경 대비)
if ! curl -fsS http://localhost:11434/api/version >/dev/null 2>&1; then
  log "ollama 서버 기동 (백그라운드)"
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q '^ollama'; then
    $SUDO systemctl enable --now ollama || true
  fi
  # 그래도 안 떠 있으면 직접 띄움
  if ! curl -fsS http://localhost:11434/api/version >/dev/null 2>&1; then
    nohup ollama serve >"$ROOT/ollama.log" 2>&1 &
  fi
  # 최대 30초 대기
  for _ in $(seq 1 30); do
    curl -fsS http://localhost:11434/api/version >/dev/null 2>&1 && break
    sleep 1
  done
fi
curl -fsS http://localhost:11434/api/version >/dev/null 2>&1 \
  && ok "ollama 서버 응답 OK" \
  || warn "ollama 서버가 응답하지 않음 — 'ollama serve' 를 수동 실행하세요"

# -----------------------------------------------------------------------------
# 4) 모델 pull
# -----------------------------------------------------------------------------
log "4/5  모델 pull: $MODEL"
if ollama list 2>/dev/null | awk '{print $1}' | grep -qx "$MODEL"; then
  ok "$MODEL 이미 존재"
else
  ollama pull "$MODEL"
fi

# -----------------------------------------------------------------------------
# 5) test.py 실행
# -----------------------------------------------------------------------------
log "5/5  llm/test.py 실행 (응답 확인)"
# venv 의 ollama 파이썬 패키지를 사용
if [ -x "$VENV/bin/python" ]; then
  PY="$VENV/bin/python"
else
  PY="python3"
  "$PY" -m pip install --quiet ollama || warn "ollama 파이썬 패키지 설치 실패"
fi

"$PY" "$ROOT/llm/test.py"

log "✅ 셋업 완료"
echo "  - Suricata : $ROOT/scripts/run_suricata.sh <pcap>"
echo "  - Zeek     : $ROOT/scripts/run_zeek.sh <pcap>"
echo "  - 모델     : $MODEL"
