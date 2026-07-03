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
NUM_CTX = int(os.environ.get("NUM_CTX", "24576"))
TEMPERATURE = float(os.environ.get("TEMPERATURE", "0.3"))
SEED = int(os.environ.get("SEED", "42"))

# ollama chat 에 그대로 넘기는 옵션
OPTS = {"temperature": TEMPERATURE, "seed": SEED, "num_ctx": NUM_CTX}

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
        #   mac 은 LLM 이 hosts[] 에서 그대로 복사; run.py attach_mac 이 evidence 조인으로 재검증(전사 오염 교정)
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
    },
    # patient_zero/anomaly_analysis 를 선택으로 두면 format 강제 모델이 곧잘 생략함
    # (patient-zero 미스가 이 파이프라인의 고질 오류라 필수로 강제)
    "required": ["executive_summary", "victims", "iocs", "timeline",
                 "patient_zero", "anomaly_analysis", "assessment"],
}
