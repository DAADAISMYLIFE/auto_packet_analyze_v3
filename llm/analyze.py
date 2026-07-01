"""
분석 오케스트레이터 (pipeline step4, FR-B).

  python3 analyze.py <name>
    입력:  output/<name>/evidence.json  (build_evidence.py 산출)
    출력:  output/<name>/analysis.json  (step5 보고서가 소비)

흐름:
  evidence 로드 → 각 stage 순차 실행(각 stage = evidence 전체 + focus 지시
  + tool 드릴다운 + structured output) → 후반 stage 는 앞 stage 출력을 입력으로
  → 전부 수집해 analysis.json 저장.
"""
import json
import os
import re
import sys

from ollama import chat

import tools

# ── 모델 설정 (FR-2) ──
MODEL = os.environ.get("MODEL", "gemma4:26b")
TEMPERATURE = 0.3          # 사실판단 → 낮게
MAX_TOOL_TURNS = 8         # tool 루프 무한방지 (FR-4)
NUM_CTX_MIN = 8192
NUM_CTX_MAX = 65536

SYSTEM_PROMPT = (
    "너는 네트워크 포렌식 분석가다. 주어진 evidence(정규화된 사실)를 근거로 판단하라. "
    "IP·도메인·해시 등 모든 지표는 evidence 나 tool 결과에 실재해야 한다. 절대 지어내지 마라. "
    "확실치 않으면 제공된 tool 로 raw 로그를 조회한 뒤 판단하라. 모든 분석은 한국어로 한다."
)


# ---------------------------------------------------------------------------
# stage 정의 (FR-5): focus 지시 + 출력 JSON Schema(FR-7) + 앞 stage 사용 여부
# ---------------------------------------------------------------------------
STAGES = [
    {
        "name": "victim_identity",
        "instruction": "감염/피해 정황이 있는 내부 호스트의 신원(ip/mac/hostname/username)을 "
                       "확정하고 각 호스트의 역할(victim/domain_controller/gateway 등)을 지정하라.",
        "uses_prior": [],
        "schema": {
            "type": "object",
            "properties": {
                "hosts": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "ip": {"type": "string"},
                            "mac": {"type": "string"},
                            "hostname": {"type": "string"},
                            "username": {"type": "string"},
                            "role": {"type": "string"},
                        },
                        "required": ["ip", "role"],
                    },
                }
            },
            "required": ["hosts"],
        },
    },
    {
        "name": "attack_assessment",
        "instruction": "공격자 endpoint(외부 IP/도메인)와 각 피해 호스트가 감염된 멀웨어 및 "
                       "관측된 공격 행위(다운로드/C2/측면이동 등)를 판단하라.",
        "uses_prior": ["victim_identity"],
        "schema": {
            "type": "object",
            "properties": {
                "host_findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "ip": {"type": "string"},
                            "malware": {"type": "array", "items": {"type": "string"}},
                            "behaviors": {"type": "array", "items": {"type": "string"}},
                        },
                        "required": ["ip"],
                    },
                },
                "attacker_endpoints": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "indicator": {"type": "string"},
                            "type": {"type": "string"},
                            "role": {"type": "string"},
                        },
                        "required": ["indicator", "type"],
                    },
                },
            },
            "required": ["host_findings"],
        },
    },
    {
        "name": "infection_timeline",
        "instruction": "감염 경로를 시간순 타임라인/시나리오로 구성하라. "
                       "각 이벤트에 시각·주체·행위를 명시하라.",
        "uses_prior": ["victim_identity", "attack_assessment"],
        "schema": {
            "type": "object",
            "properties": {
                "events": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "ts": {"type": "string"},
                            "actor": {"type": "string"},
                            "action": {"type": "string"},
                            "detail": {"type": "string"},
                        },
                        "required": ["action"],
                    },
                },
                "summary": {"type": "string"},
            },
            "required": ["events"],
        },
    },
    {
        "name": "block_policy",
        "instruction": "확정된 IOC(외부 IP/도메인/URL/파일해시)로 차단정책(패턴)을 생성하라. "
                       "각 규칙에 차단 대상 값과 근거를 명시하라.",
        "uses_prior": ["attack_assessment", "infection_timeline"],
        "schema": {
            "type": "object",
            "properties": {
                "rules": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "type": {"type": "string"},       # ip|domain|url|sha256
                            "value": {"type": "string"},
                            "reason": {"type": "string"},
                        },
                        "required": ["type", "value", "reason"],
                    },
                }
            },
            "required": ["rules"],
        },
    },
]


# ---------------------------------------------------------------------------
# 로드 / 설정
# ---------------------------------------------------------------------------
def load_evidence(base):
    """output/<name>/evidence.json 로드 → dict."""
    path = os.path.join(base, "evidence.json")
    if not os.path.isfile(path):
        raise SystemExit(f"evidence.json 없음: {path} (scripts/build_evidence.py 먼저 실행)")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _compact(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def compute_num_ctx(evidence):
    """evidence 가 통째로 들어갈 num_ctx 산정 (FR-2).
    토큰 ~= 문자/4. system + tool 결과 + 추론 + 출력 여유를 더하고 1024 단위 올림·클램프.
    """
    ev_tokens = len(_compact(evidence)) // 4
    need = ev_tokens + 8000                    # 여유(도구결과/추론/출력)
    ctx = ((need + 1023) // 1024) * 1024
    return max(NUM_CTX_MIN, min(ctx, NUM_CTX_MAX))


# ---------------------------------------------------------------------------
# tool 호출 루프 (FR-4)
# ---------------------------------------------------------------------------
def run_tool_loop(messages, num_ctx):
    """모델 호출 → tool_calls 있으면 실행·주입·재호출 → 없을 때까지(최대 MAX_TOOL_TURNS).
    tool 을 쓰며 추론하게 하는 단계 (structured output 아님)."""
    res = None
    for _ in range(MAX_TOOL_TURNS):
        res = chat(model=MODEL, messages=messages, tools=tools.TOOLS,
                   options={"temperature": TEMPERATURE, "num_ctx": num_ctx})
        if not res.message.tool_calls:
            return res
        messages.append(res.message)
        for tc in res.message.tool_calls:
            name = tc.function.name
            fn = tools.AVAILABLE.get(name)
            try:
                result = fn(**tc.function.arguments) if fn else {"error": f"unknown tool: {name}"}
            except Exception as e:                       # tool 실패도 데이터로 (FR-C3)
                result = {"error": f"tool 실행 실패: {e}"}
            messages.append({"role": "tool", "tool_name": name,
                             "content": json.dumps(result, ensure_ascii=False, default=str)})
    return res      # 턴 캡 도달 — 마지막 응답 반환


# ---------------------------------------------------------------------------
# stage 실행 (FR-5,6,7,8,10)
# ---------------------------------------------------------------------------
def build_stage_messages(stage, evidence, prior_outputs):
    """system(역할/그라운딩) + user(evidence 전체 + focus + 필요시 앞 stage 출력)."""
    parts = [f"[분석 목표]\n{stage['instruction']}", "",
             "[evidence]", _compact(evidence)]
    for k in stage["uses_prior"]:                        # FR-6
        if k in prior_outputs:
            parts += ["", f"[이전 단계 결과: {k}]", _compact(prior_outputs[k])]
    return [{"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "\n".join(parts)}]


def parse_structured(content):
    """모델 출력 문자열 → dict. 실패 시 None."""
    try:
        return json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return None


def run_stage(stage, evidence, prior_outputs, num_ctx):
    """한 stage: 메시지 구성 → tool 루프(추론) → structured output 추출 → 그라운딩 검증."""
    messages = build_stage_messages(stage, evidence, prior_outputs)
    run_tool_loop(messages, num_ctx)                     # 추론 + 드릴다운

    # structured output 추출 (FR-7). 잘못된 JSON 이면 재시도 (FR-10)
    messages.append({"role": "user",
                     "content": "위 분석 결과를 지정된 JSON 스키마로만 출력하라. "
                                "근거(evidence/tool)가 없는 값은 포함하지 마라."})
    output, res = None, None
    for _ in range(2):
        res = chat(model=MODEL, messages=messages, format=stage["schema"],
                   options={"temperature": TEMPERATURE, "num_ctx": num_ctx})
        output = parse_structured(res.message.content)
        if output is not None:
            break
        messages.append({"role": "user",
                         "content": "유효한 JSON 이 아니다. 스키마에 맞는 JSON 만 다시 출력하라."})
    if output is None:
        return {"_error": "structured output 파싱 실패",
                "raw": res.message.content if res else None}

    warnings = check_grounding(output, evidence)         # FR-8
    if warnings:
        output["_grounding_warnings"] = warnings
    return output


# ---------------------------------------------------------------------------
# 그라운딩 검증 (FR-8) — 지어낸 IP/해시 탐지 (경고)
# ---------------------------------------------------------------------------
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


def _iter_strings(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_strings(v)
    elif isinstance(obj, str):
        yield obj


def check_grounding(output, evidence):
    """출력의 IP/sha256 이 evidence 텍스트에 실재하는지 검증 → 없으면 경고 리스트.
    (도메인은 파생/정규화 변형이 많아 오탐이 커서 v1 에서는 IP·해시만 검사)"""
    ev_text = _compact(evidence).lower()
    warnings, seen = [], set()
    for s in _iter_strings(output):
        for rx, kind in ((_HASH_RE, "hash"), (_IP_RE, "ip")):
            for m in rx.findall(s):
                val = m.lower()
                if val in seen:
                    continue
                seen.add(val)
                if val not in ev_text:
                    warnings.append({"value": m, "kind": kind, "note": "evidence 에 없음"})
    return warnings


# ---------------------------------------------------------------------------
# 오케스트레이션 (FR-9,11)
# ---------------------------------------------------------------------------
def analyze(name, root):
    """전체 stage 를 순서대로 실행하고 결과를 모아 반환."""
    base = os.path.join(root, "output", name)
    tools.set_context(base)                              # FR-3
    evidence = load_evidence(base)
    num_ctx = compute_num_ctx(evidence)
    print(f"[analyze] {name}  num_ctx={num_ctx}  model={MODEL}")

    outputs = {}
    for stage in STAGES:
        prior = {k: outputs[k] for k in stage["uses_prior"] if k in outputs}
        print(f"  - stage: {stage['name']} ...")
        outputs[stage["name"]] = run_stage(stage, evidence, prior, num_ctx)   # FR-11

    return {"pcap": name, "model": MODEL, "stages": outputs}


def main():
    if len(sys.argv) < 2:
        raise SystemExit("사용법: python3 analyze.py <name>")
    name = sys.argv[1]
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # llm/ 의 부모
    result = analyze(name, root)
    out = os.path.join(root, "output", name, "analysis.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"[analyze] 저장: {out}")


if __name__ == "__main__":
    main()
