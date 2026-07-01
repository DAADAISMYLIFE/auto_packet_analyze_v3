"""
Analysis orchestrator (pipeline step 4, FR-B).

  python3 analyze.py <name>
    input:  output/<name>/evidence.json   (from build_evidence.py)
    output: output/<name>/analysis.json   (consumed by step 5 report)
            output/<name>/analyze_trace.json  (full debug trace)

Flow:
  load evidence -> run each stage in order (each stage = full evidence + focused
  instruction + tool drill-down + structured output) -> later stages take earlier
  stage outputs as input -> collect all into analysis.json.

Everything in this stage is done in ENGLISH (to maximize model comprehension);
only the final human report (step 5) is Korean.
"""
import json
import os
import re
import sys

from ollama import chat

import tools

# ── model config (FR-2) ──
MODEL = os.environ.get("MODEL", "gemma4:26b")
TEMPERATURE = 0.3          # factual judgment -> low
MAX_TOOL_TURNS = 8         # tool-loop guard (FR-4)
NUM_CTX_MIN = 8192
NUM_CTX_MAX = 65536

# ── project overview + role (shared across stages -> system message) ──
SYSTEM_PROMPT = (
    "# Project overview\n"
    "You are the 'analysis' stage of an automated network-forensics pipeline. "
    "The machine has already done pcap -> (Suricata/Zeek) -> evidence (a JSON of "
    "deterministically extracted FACTS). Your job is to reason over this evidence to "
    "determine the incident. The final deliverables are victim identity, attacker, "
    "attack behavior, timeline, and blocking policy; you handle part of it now.\n\n"
    "# Role\n"
    "You are a network forensics analyst.\n"
    "- Base every judgment ONLY on the provided evidence and tool-query results.\n"
    "- NEVER invent IPs, domains, hashes, hostnames, or usernames from prior knowledge or guessing.\n"
    "- Do not output any value that does not appear verbatim in the evidence.\n"
    "- If something is unknown, leave it empty (null/omit). Empty is better than fabricated.\n"
    "- Reason in English."
)


# ---------------------------------------------------------------------------
# stage definitions (FR-5): focused instruction + output JSON Schema (FR-7)
# ---------------------------------------------------------------------------
STAGES = [
    {
        "name": "victim_identity",
        "instruction": (
            "[Goal] Determine the identities of the victim / internal hosts.\n"
            "# Methodology\n"
            "1. Read the evidence.hosts array. Internal host identities exist ONLY there.\n"
            "2. For each host, copy ip/mac/hostname/username/ad_domain VERBATIM from the "
            "evidence. Do not transform, normalize, or fill in missing values.\n"
            "3. Assign role: hostname ending in '-DC', or kerberos service centered on "
            "krbtgt/ldap -> domain_controller; a workstation involved in "
            "alerts/external contact/file download -> victim; otherwise -> gateway/server. "
            "Judge role from context, but NEVER fabricate identity fields (ip/mac, etc.).\n"
            "4. If an identity is uncertain, call get_host_info(ip=...) to query raw logs, then decide.\n"
            "5. Output ONLY the specified JSON schema. No prose."
        ),
        "input_example": (
            '{"hosts":[{"ip":"10.20.30.40","mac":"aa:bb:cc:dd:ee:ff","hostname":"PC-KIM",'
            '"username":"kim.minsu","ad_domain":"CORP.LOCAL"},'
            '{"ip":"10.20.30.5","mac":"11:22:33:44:55:66","hostname":"CORP-DC",'
            '"username":null,"ad_domain":null}],'
            '"alerts":[{"signature":"ET MALWARE ...","severity":1,"src_ips":["10.20.30.40"]}]}'
        ),
        "output_example": (
            '{"hosts":[{"ip":"10.20.30.40","mac":"aa:bb:cc:dd:ee:ff","hostname":"PC-KIM",'
            '"username":"kim.minsu","role":"victim"},'
            '{"ip":"10.20.30.5","mac":"11:22:33:44:55:66","hostname":"CORP-DC",'
            '"username":null,"role":"domain_controller"}]}'
        ),
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
        "instruction": (
            "[Goal] Determine attacker endpoints (external IPs/domains) and, for each victim "
            "host, the malware and observed attack behaviors (download / C2 / lateral movement).\n"
            "Base everything on evidence.alerts / evidence.external / evidence.files / "
            "evidence.lateral_movement. Malware family names usually come directly from the "
            "alert 'signature' text (e.g. 'ET MALWARE Cobalt Strike ...'). Use tools to drill "
            "down when needed. Output ONLY the specified JSON schema."
        ),
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
        "instruction": (
            "[Goal] Reconstruct the infection chain as a chronological timeline / scenario. "
            "For each event include timestamp, actor, and action. Order strictly by time using "
            "the ts fields in the evidence. Output ONLY the specified JSON schema."
        ),
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
        "instruction": (
            "[Goal] Generate blocking rules (patterns) from the confirmed IOCs "
            "(external IPs / domains / URLs / file hashes). Each rule needs the value to block "
            "and the reason. Only use IOC values that appear verbatim in the evidence. "
            "Output ONLY the specified JSON schema."
        ),
        "uses_prior": ["attack_assessment", "infection_timeline"],
        "schema": {
            "type": "object",
            "properties": {
                "rules": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "type": {"type": "string"},       # ip | domain | url | sha256
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
# debug trace (FR: full visibility into requests / responses / thinking / tools)
# ---------------------------------------------------------------------------
TRACE = []                 # list of per-stage trace dicts


def _msg_dict(m):
    """ollama message -> plain dict (for logging)."""
    d = {"role": getattr(m, "role", None), "content": getattr(m, "content", None)}
    think = getattr(m, "thinking", None)
    if think:
        d["thinking"] = think
    tcs = getattr(m, "tool_calls", None)
    if tcs:
        d["tool_calls"] = [{"name": tc.function.name, "arguments": dict(tc.function.arguments)}
                           for tc in tcs]
    return d


# ---------------------------------------------------------------------------
# load / config
# ---------------------------------------------------------------------------
def load_evidence(base):
    path = os.path.join(base, "evidence.json")
    if not os.path.isfile(path):
        raise SystemExit(f"evidence.json missing: {path} (run scripts/build_evidence.py first)")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _compact(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def compute_num_ctx(evidence):
    """Size num_ctx so the whole evidence fits (FR-2). ~= chars/4 + headroom, clamped."""
    ev_tokens = len(_compact(evidence)) // 4
    need = ev_tokens + 8000
    ctx = ((need + 1023) // 1024) * 1024
    return max(NUM_CTX_MIN, min(ctx, NUM_CTX_MAX))


# ---------------------------------------------------------------------------
# ollama call helpers (capture thinking when supported)
# ---------------------------------------------------------------------------
def _reason_chat(messages, num_ctx):
    """Tool-enabled reasoning call. Requests thinking; falls back if unsupported."""
    kw = dict(model=MODEL, messages=messages, tools=tools.TOOLS,
              options={"temperature": TEMPERATURE, "num_ctx": num_ctx})
    try:
        return chat(**kw, think=True)
    except TypeError:
        return chat(**kw)


# ---------------------------------------------------------------------------
# tool loop (FR-4) — logs every turn/thinking/tool call into stage_trace
# ---------------------------------------------------------------------------
def run_tool_loop(messages, num_ctx, stage_trace):
    res = None
    for turn in range(MAX_TOOL_TURNS):
        res = _reason_chat(messages, num_ctx)
        stage_trace["turns"].append(_msg_dict(res.message))
        think_len = len(getattr(res.message, "thinking", "") or "")
        n_tc = len(res.message.tool_calls or [])
        print(f"      turn {turn}: thinking={think_len}c tool_calls={n_tc}")

        if not res.message.tool_calls:
            return res
        messages.append(res.message)
        for tc in res.message.tool_calls:
            name = tc.function.name
            args = dict(tc.function.arguments)
            fn = tools.AVAILABLE.get(name)
            try:
                result = fn(**args) if fn else {"error": f"unknown tool: {name}"}
            except Exception as e:                       # tool failure as data (FR-C3)
                result = {"error": f"tool execution failed: {e}"}
            stage_trace["tool_results"].append({"name": name, "arguments": args, "result": result})
            print(f"         tool {name}({args}) -> {str(result)[:80]}")
            messages.append({"role": "tool", "tool_name": name,
                             "content": json.dumps(result, ensure_ascii=False, default=str)})
    return res      # hit turn cap


# ---------------------------------------------------------------------------
# stage execution (FR-5,6,7,8,10)
# ---------------------------------------------------------------------------
def build_stage_messages(stage, evidence, prior_outputs):
    """system(overview/role) + user(methodology -> examples -> real evidence -> prior)."""
    parts = [stage["instruction"]]
    if stage.get("input_example"):
        parts += ["", "# Input example (format only - NOT real values)", stage["input_example"]]
    if stage.get("output_example"):
        parts += ["", "# Output example (correct answer for the input above)", stage["output_example"]]
    parts += ["", "# Actual evidence (perform the task on THIS; take values only from here)",
              _compact(evidence)]
    for k in stage["uses_prior"]:                        # FR-6
        if k in prior_outputs:
            parts += ["", f"# Prior stage result: {k}", _compact(prior_outputs[k])]
    return [{"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "\n".join(parts)}]


def parse_structured(content):
    try:
        return json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return None


def run_stage(stage, evidence, prior_outputs, num_ctx):
    stage_trace = {"stage": stage["name"], "request": None,
                   "turns": [], "tool_results": [],
                   "structured_raw": None, "output": None, "grounding_warnings": []}
    messages = build_stage_messages(stage, evidence, prior_outputs)
    stage_trace["request"] = [{"role": m["role"], "content": m["content"]} for m in messages]

    run_tool_loop(messages, num_ctx, stage_trace)        # reasoning + drill-down

    # structured output extraction (FR-7); retry on invalid JSON (FR-10)
    messages.append({"role": "user",
                     "content": "Now output ONLY the JSON matching the specified schema. "
                                "Do not include any value not grounded in the evidence or tool results."})
    output, res = None, None
    for _ in range(2):
        res = chat(model=MODEL, messages=messages, format=stage["schema"],
                   options={"temperature": TEMPERATURE, "num_ctx": num_ctx})
        stage_trace["structured_raw"] = res.message.content
        output = parse_structured(res.message.content)
        if output is not None:
            break
        messages.append({"role": "user",
                         "content": "That was not valid JSON. Output only JSON matching the schema."})
    if output is None:
        stage_trace["output"] = {"_error": "structured output parse failed"}
        TRACE.append(stage_trace)
        return stage_trace["output"]

    warnings = check_grounding(output, evidence)         # FR-8
    if warnings:
        output["_grounding_warnings"] = warnings
        stage_trace["grounding_warnings"] = warnings
    stage_trace["output"] = output
    TRACE.append(stage_trace)
    return output


# ---------------------------------------------------------------------------
# grounding check (FR-8) — detect fabricated IPs / hashes (warning only)
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
                    warnings.append({"value": m, "kind": kind, "note": "not in evidence"})
    return warnings


# ---------------------------------------------------------------------------
# orchestration (FR-9,11)
# ---------------------------------------------------------------------------
def analyze(name, root):
    base = os.path.join(root, "output", name)
    tools.set_context(base)                              # FR-3
    evidence = load_evidence(base)
    num_ctx = compute_num_ctx(evidence)
    TRACE.clear()
    print(f"[analyze] {name}  num_ctx={num_ctx}  model={MODEL}")

    outputs = {}
    for stage in STAGES:
        prior = {k: outputs[k] for k in stage["uses_prior"] if k in outputs}
        print(f"  - stage: {stage['name']} ...")
        outputs[stage["name"]] = run_stage(stage, evidence, prior, num_ctx)
        if outputs[stage["name"]].get("_grounding_warnings"):
            print(f"    ! grounding warnings: {outputs[stage['name']]['_grounding_warnings']}")

    return {"pcap": name, "model": MODEL, "stages": outputs}


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: python3 analyze.py <name>")
    name = sys.argv[1]
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # parent of llm/
    result = analyze(name, root)

    out_dir = os.path.join(root, "output", name)
    with open(os.path.join(out_dir, "analysis.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "analyze_trace.json"), "w", encoding="utf-8") as f:
        json.dump(TRACE, f, ensure_ascii=False, indent=2, default=str)
    print(f"[analyze] wrote analysis.json + analyze_trace.json in {out_dir}")


if __name__ == "__main__":
    main()
