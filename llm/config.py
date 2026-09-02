"""
파이프라인 설정 한 곳 모음 (모델 / 튜너블 / 프롬프트).

- 스칼라 설정은 리포 루트의 `.env` 에서 읽는다 (없으면 아래 기본값).
  → 모델 베이크오프: `.env` 의 MODEL 만 바꿔 재실행하면 됨 (코드 수정 X).
- 시스템 프롬프트는 `llm/prompts/*.md` 텍스트 파일에서 읽는다
  → 프롬프트 수정 시 run.py 를 건드리지 않는다.

의존성 없음: python-dotenv 대신 자체 파서 사용.
"""
import os
from pathlib import Path

_DIR = Path(__file__).resolve().parent          # llm/
_PROMPTS = _DIR / "prompts"
_ENV = _DIR.parent / ".env"                      # 리포 루트/.env


def _load_dotenv(path: Path):
    """KEY=VALUE 형식의 .env 를 os.environ 에 주입 (이미 있는 값은 덮지 않음)."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


_load_dotenv(_ENV)

# ── 모델 / 튜너블 ──
MODEL = os.environ.get("MODEL", "gemma4:26b")
NUM_CTX = int(os.environ.get("NUM_CTX", "65536"))   # evidence 안 잘리게 크게 (VRAM 되면 NUM_CTX=131072 로 더)
TEMPERATURE = float(os.environ.get("TEMPERATURE", "0.3"))
TOP_P = float(os.environ.get("TOP_P", "0.95"))
SEED = int(os.environ.get("SEED", "42"))
# ── 추론(thinking) 강도 ──
# ollama 는 qwen3.8 전용 네이티브 렌더러(model/renderers/qwen35.go)로 추론 강도를 지원한다.
# reasoning_effort 의 정체는 토큰 예산이 아니라 '템플릿에 끼워넣는 지침 문장'이다:
#   true/high/max → xhigh 지침("철저히 검토·더블체크") 주입 = 최대 사고 (기본값이 이거라 과잉사고)
#   medium       → 지침 없음(모델 본연 판단). 복잡 과제 실측: 토큰 40~60% 절감, 완성도 소폭 하락
#   low          → "빨리 결론" 지침. 복잡 과제에서 오히려 토큰 폭증+자가검증 루프 실측 — 포렌식 금지
#   false        → 사고 자체를 끔. reasoning 모델의 판단력이 급감(q2 실측: 광고를 IOC 로) — 금지
# 주의: ollama 는 think=false 일 때 format(스키마 강제)을 조용히 무시한 버그 이력(#14645/#15260).
def _parse_think(value, default):
    v = str(value if value is not None else default).strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    if v in ("low", "medium", "high", "max"):
        return v
    raise SystemExit(f"THINK={value!r} 인식 불가 — true/false/low/medium/high/max 중 하나")


THINK = _parse_think(os.environ.get("THINK"), "medium")
# 서술(render_report) 전용 — 3문장 요약엔 사고가 낭비(호출당 수 분). 파싱 실패 시 render 가 자동 재시도.
THINK_NARRATIVE = _parse_think(os.environ.get("THINK_NARRATIVE"), "false")

TOP_K = int(os.environ.get("TOP_K", "20"))            # qwen3.8 모델카드 권장 20 (ollama 기본 40)
# 폭주 차단기 — 사고+출력 합계 상한. 실측 정상 케이스가 사고≈7k+출력≈4k 이므로 넉넉히 잡는다.
#   너무 낮으면 사고가 예산을 다 먹고 본답이 안 나온다(ollama #14793 — 빈 응답/루프).
NUM_PREDICT = int(os.environ.get("NUM_PREDICT", "16000"))
# num_batch 는 넣지 않는다(ollama 기본 512). 1024 로 올렸다가 ctx 131072 컴퓨트 버퍼가
#   T4 잔여 VRAM(카드당 4~5GB)을 넘겨 조용한 CPU 스필 → 디코드 붕괴 실측(2026-09-02, q2 30분+).
#   진단 셀은 num_batch 없이 돌아서 못 잡았다 — OPTS 를 바꿀 땐 러너 재적재를 유발하는
#   옵션(num_ctx/num_batch)인지 확인하고 진단과 동일 옵션으로 검증할 것.

# ollama chat 에 그대로 넘기는 옵션
OPTS = {"temperature": TEMPERATURE, "top_p": TOP_P, "top_k": TOP_K, "seed": SEED,
        "num_ctx": NUM_CTX, "num_predict": NUM_PREDICT}

# ── 시스템 프롬프트 (파일에서 로드) ──
SYSTEM_PROMPT_TRIAGE = (_PROMPTS / "triage.md").read_text(encoding="utf-8")
SYSTEM_PROMPT_FORENSIC = (_PROMPTS / "forensic.md").read_text(encoding="utf-8")

# ── triage 출력 스키마 (ollama format 강제) ──
VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"enum": ["no_incident", "suspicious", "confirmed"]},
        "grounds": {"type": "array", "items": {"type": "string"},
                    "maxItems": 6,
                    "description": "specific evidence values that drove the verdict"},
    },
    "required": ["verdict", "grounds"],
}

# ── forensic 출력 스키마 (ollama format 강제 → 산문 대신 구조화 JSON) ──
#   채점(JSON↔truth 비교)과 렌더링(JSON→보고서)의 공통 입력이 된다.
REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "executive_summary": {"type": "string"},
        # 내부 호스트 전수 (인프라 포함) — 코드가 아니라 LLM 이 채우되 status 로 구분
        #   mac/hostname/username 은 run.py attach_identity 가 evidence 의 ip 조인으로 덮어씀
        #   (LLM 전사 오염·optional 생략 방지 — status/malware 만 LLM 판단으로 남김)
        "victims": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string"},
                    "mac": {"type": ["string", "null"]},
                    "hostname": {"type": "string"},
                    "username": {"type": "string"},
                    "role": {"type": "string"},
                    "status": {"enum": ["compromised", "infrastructure", "clean", "unknown"]},
                    "malware": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["ip", "status"],
            },
        },
        "iocs": {
            "type": "object",
            "properties": {
                "c2": {"type": "array", "items": {"type": "string"}},
                "delivery": {"type": "array", "items": {"type": "string"}},
                "exfil": {"type": "array", "items": {"type": "string"}},
                "domains": {"type": "array", "items": {"type": "string"}},
                "hashes": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["c2", "delivery", "exfil", "domains", "hashes"],
        },
        "timeline": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    # epoch 초 — evidence 의 first_ts 숫자를 그대로 복사 (변환/재타이핑 금지)
                    "ts": {"type": "number"},
                    "host": {"type": "string"},
                    "event": {"type": "string"},
                },
                "required": ["ts", "event"],
            },
        },
        "patient_zero": {"type": "string"},
        "anomaly_analysis": {"type": "array", "items": {"type": "string"}},
        "assessment": {"type": "string"},
        # 위협 종류에 무관한 공격 기록 — 멀웨어 iocs 모델이 못 담는 사건
        #   (웹공격/스캔/브루트포스/피벗 등)을 actor/target/technique 로 표현한다.
        #   target(피격자)은 IOC 가 아니므로 iocs 에 넣지 않는다(자기/피해 서버 차단 방지).
        #   actor_scope/target_scope 는 run.py annotate_attacks 가 host inventory 로
        #   채운다(내부/외부는 결정론적) → 차단 반응 분기(내부 actor=호스트격리 /
        #   외부 actor=IP차단)의 근거. optional(순수 멀웨어 케이스는 생략/[]).
        "attacks": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "technique": {"type": "string"},
                    "actor": {"type": "string"},
                    "target": {"type": "string"},
                    "target_host": {"type": "string"},
                    "sample_uri": {"type": "string"},
                    "disposition": {"enum": ["succeeded", "attempted", "unknown"]},
                    "actor_scope": {"enum": ["internal", "external", "unknown"]},
                    "target_scope": {"enum": ["internal", "external", "unknown"]},
                },
                "required": ["technique", "actor", "target"],
            },
        },
    },
    # patient_zero/anomaly_analysis 를 선택으로 두면 format 강제 모델이 곧잘 생략함
    # (patient-zero 미스가 이 파이프라인의 고질 오류라 필수로 강제)
    "required": ["executive_summary", "victims", "iocs", "timeline",
                 "patient_zero", "anomaly_analysis", "assessment"],
}
