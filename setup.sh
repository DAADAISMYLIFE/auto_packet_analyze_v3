#!/usr/bin/env bash
# =============================================================================
# auto_packet_analyze_v3 setup — 조용한 멱등 설치
#   - 전부 깔려 있으면 몇 초 안에 통과한다 (항상 다시 실행해도 됨).
#   - 상세 출력(apt/다운로드 진행바)은 전부 setup.log 로 보내고,
#     화면에는 ✓(설치됨) / ∙(건너뜀) / ✗(실패) 한 줄씩만 찍는다.
#   - LLM 스모크 콜은 하지 않는다 — 모델 응답/format 검증은 노트북 진단 셀이
#     파이프라인과 '동일 옵션'으로 수행한다 (여기서 하면 중복 + 수 분 낭비).
# 사용법: ./setup.sh            (MODEL 환경변수로 모델 덮어쓰기)
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
MODEL="${MODEL:-gemma4:26b}"
LOG="$ROOT/setup.log"
: > "$LOG"
FAILED=0

if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi
log()   { echo -e "\033[1;36m[setup]\033[0m $*"; }
ok()    { echo -e "  \033[1;32m✓\033[0m $*"; }
skip()  { echo -e "  \033[1;90m∙\033[0m $* — 이미 있음, 건너뜀"; }
fail()  { echo -e "  \033[1;31m✗\033[0m $* — $LOG 끝부분 확인"; FAILED=1; }
quiet() { "$@" >>"$LOG" 2>&1; }

APT_UPDATED=0
apt_prep() {   # 설치할 게 있을 때만, 한 번만 apt update
  [ "$APT_UPDATED" = 1 ] && return 0
  quiet $SUDO apt-get update -y && APT_UPDATED=1
}

# ── 1) Suricata + ET Open 룰 ─────────────────────────────────────────────────
if command -v suricata >/dev/null 2>&1; then
  skip "suricata"
else
  log "suricata 설치 중…"
  apt_prep
  quiet $SUDO apt-get install -y curl gnupg ca-certificates lsb-release \
        software-properties-common zstd
  quiet $SUDO add-apt-repository -y ppa:oisf/suricata-stable
  quiet $SUDO apt-get update -y
  quiet $SUDO apt-get install -y suricata && ok "suricata" || fail "suricata"
fi
if [ -s /var/lib/suricata/rules/suricata.rules ]; then
  skip "ET Open 룰"
else
  log "ET Open 룰 다운로드 중…"
  quiet $SUDO suricata-update --no-test \
    && ok "ET Open 룰" || fail "ET Open 룰 (run_suricata.sh 는 yaml 기본 룰로 폴백)"
fi

# ── 2) Zeek ──────────────────────────────────────────────────────────────────
if command -v zeek >/dev/null 2>&1; then
  skip "zeek"
else
  log "zeek 설치 중…"
  UBU="$(. /etc/os-release && echo "${VERSION_ID}")"
  ZREPO="https://download.opensuse.org/repositories/security:/zeek/xUbuntu_${UBU}"
  apt_prep
  quiet $SUDO mkdir -p /etc/apt/keyrings
  { curl -fsSL "${ZREPO}/Release.key" | gpg --dearmor \
      | $SUDO tee /etc/apt/keyrings/zeek.gpg >/dev/null; } 2>>"$LOG"
  echo "deb [signed-by=/etc/apt/keyrings/zeek.gpg] ${ZREPO}/ /" \
    | $SUDO tee /etc/apt/sources.list.d/security-zeek.list >/dev/null
  quiet $SUDO apt-get update -y
  quiet $SUDO apt-get install -y zeek
  if [ -x /opt/zeek/bin/zeek ] && ! command -v zeek >/dev/null 2>&1; then
    $SUDO ln -sf /opt/zeek/bin/zeek /usr/local/bin/zeek
    $SUDO ln -sf /opt/zeek/bin/zeek-cut /usr/local/bin/zeek-cut 2>/dev/null || true
  fi
  command -v zeek >/dev/null 2>&1 && ok "zeek" || fail "zeek"
fi

# ── 3) Ollama 런타임 + 서버 ──────────────────────────────────────────────────
if command -v ollama >/dev/null 2>&1; then
  skip "ollama"
else
  log "ollama 설치 중…"
  { curl -fsSL https://ollama.com/install.sh | sh; } >>"$LOG" 2>&1 \
    && ok "ollama" || fail "ollama"
fi
if curl -fsS http://localhost:11434/api/version >/dev/null 2>&1; then
  skip "ollama 서버"
else
  log "ollama 서버 기동…"
  nohup ollama serve >>"$LOG" 2>&1 &
  for _ in $(seq 1 30); do
    curl -fsS http://localhost:11434/api/version >/dev/null 2>&1 && break
    sleep 1
  done
  curl -fsS http://localhost:11434/api/version >/dev/null 2>&1 \
    && ok "ollama 서버" || fail "ollama 서버"
fi

# ── 4) 모델 + 파이썬 의존성 ──────────────────────────────────────────────────
if ollama list 2>/dev/null | awk '{print $1}' | grep -qx "$MODEL"; then
  skip "모델 $MODEL"
else
  log "모델 pull: $MODEL (진행바는 $LOG 로 — 수 분~수십 분)"
  quiet ollama pull "$MODEL" && ok "모델 $MODEL" || fail "모델 $MODEL"
fi

PY="$(command -v python3)"
if "$PY" -c "import ollama" >/dev/null 2>&1; then
  skip "python ollama 클라이언트"
else
  quiet "$PY" -m pip install -qU ollama \
    || quiet "$PY" -m pip install -qU --break-system-packages ollama
  "$PY" -c "import ollama" 2>>"$LOG" \
    && ok "python ollama 클라이언트" || fail "python ollama 클라이언트"
fi
quiet "$PY" -c "import sys; sys.path.insert(0, '$ROOT/llm'); import config" \
  && ok "config 로드 (.env 유효)" || fail "config 로드 (.env 값 확인)"

if [ "$FAILED" = 0 ]; then log "✅ 셋업 완료 (모델: $MODEL)"; else log "⚠ 일부 실패 — $LOG 확인"; fi
exit "$FAILED"
