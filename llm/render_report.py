#!/usr/bin/env python3
"""
최종 한글 보고서 (파이프라인 6단계): reports/<name>.json + .rules → reports/<name>.md.

  python3 llm/render_report.py <name>

원칙(대화에서 확정):
  - 사실(피해자/IOC/타임라인/차단룰)은 코드가 표로 주입한다. LLM 이 재타이핑하면
    이번 파이프라인 내내 막아온 IP/도메인 재오염이 마지막 보고서에서 되살아나므로.
  - LLM 은 '한글 서술'(개요/시나리오/권고)만 쓴다. format 강제 단일 chat 호출.
  - ollama 가 없으면(로컬) 서술을 스텁으로 채운다 → 코드부(표/타임라인/룰 주입) 검증 가능.
"""
import sys, os, json
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # config 로컬 import

NARRATIVE_SCHEMA = {
    "type": "object",
    "properties": {
        "overview_ko": {"type": "string"},
        "scenario_ko": {"type": "string"},
        "recommendation_ko": {"type": "string"},
    },
    "required": ["overview_ko", "scenario_ko", "recommendation_ko"],
}

NARR_PROMPT = (
    "너는 네트워크 포렌식 보고서의 '서술 부분'을 쓰는 분석가다. 아래 분석 JSON 을 바탕으로 "
    "한글 서술 3개를 작성하라. IP/도메인/해시/MAC 같은 지표 값은 보고서의 표에서 코드가 "
    "이미 다루므로 문장에서 재입력하지 말고 호스트명·사용자·역할로 지칭하라. "
    "overview_ko: 무슨 일이 있었는지 2-3문장 개요. "
    "scenario_ko: 공격이 시간순으로 어떻게 전개됐는지 서술. "
    "recommendation_ko: 대응 권고와 조치."
)


def _fmt_ts(ts):
    """epoch → '사람 시간(UTC) + 원본 epoch'. (epoch 를 진실로 유지하되 사람이 읽게)"""
    try:
        return f"{datetime.fromtimestamp(float(ts), timezone.utc):%Y-%m-%d %H:%M:%S} UTC (`{ts}`)"
    except (TypeError, ValueError):
        return f"`{ts}`"


def narrative(analysis):
    """LLM 한글 서술 3필드. ollama 미가용 시 스텁(코드부 검증용)."""
    try:
        from ollama import chat
    except Exception:
        summ = analysis.get("executive_summary") or ""
        return {"overview_ko": f"(LLM 미가용 — 스텁) 영문 요약: {summ}",
                "scenario_ko": "(LLM 미가용 — 스텁) 타임라인 표 참조.",
                "recommendation_ko": "(LLM 미가용 — 스텁) 아래 차단 정책을 검토 후 적용 여부를 선택하십시오."}
    from config import MODEL, OPTS
    res = chat(model=MODEL, format=NARRATIVE_SCHEMA, think=False,
               messages=[{"role": "system", "content": NARR_PROMPT},
                         {"role": "user", "content": json.dumps(analysis, ensure_ascii=False, default=str)}],
               options=OPTS)
    try:
        return json.loads(res.message.content)
    except (json.JSONDecodeError, TypeError):
        return {"overview_ko": "", "scenario_ko": "", "recommendation_ko": ""}


def render(name, report, rules_text):
    a = report.get("analysis") or {}
    n = narrative(a)
    iocs = a.get("iocs", {})
    L = [f"# 네트워크 포렌식 보고서 — {name}\n"]

    L += ["## 1. 개요\n", (n.get("overview_ko") or "").strip() + "\n"]

    L.append("## 2. 판정\n")
    L.append(f"- **판정**: `{report.get('verdict', '?')}`")
    for g in report.get("grounds", []):
        L.append(f"- 근거: {g}")
    L.append("")

    L.append("## 3. 피해 호스트\n")
    L.append("| IP | 호스트명 | 사용자 | 역할 | 상태 | 멀웨어 |")
    L.append("|---|---|---|---|---|---|")
    for v in a.get("victims", []):
        mal = ", ".join(v.get("malware") or []) or "-"
        L.append(f"| `{v.get('ip', '')}` | {v.get('hostname') or '-'} | {v.get('username') or '-'} "
                 f"| {v.get('role') or '-'} | {v.get('status', '')} | {mal} |")
    L.append("")

    L.append("## 4. 침해지표 (IOC)\n")
    any_ioc = False
    for label, key in [("C2", "c2"), ("Delivery", "delivery"), ("Exfil", "exfil"),
                       ("도메인", "domains"), ("해시", "hashes")]:
        vals = iocs.get(key) or []
        if vals:
            any_ioc = True
            L.append(f"- **{label}**: " + ", ".join(f"`{x}`" for x in vals))
    if not any_ioc:
        L.append("- (외부 악성 지표 없음 — 아래 타임라인/시나리오 참조)")
    L.append("")

    L.append("## 5. 공격 타임라인\n")
    L.append("| 시각 | 호스트 | 이벤트 |")
    L.append("|---|---|---|")
    for e in sorted(a.get("timeline", []), key=lambda x: x.get("ts") or 0):
        L.append(f"| {_fmt_ts(e.get('ts'))} | `{e.get('host') or '-'}` | {e.get('event', '')} |")
    L.append("")

    L += ["## 6. 공격 시나리오\n", (n.get("scenario_ko") or "").strip() + "\n"]

    L.append("## 7. 차단 정책 (Suricata)\n")
    L.append("```suricata")
    L.append(rules_text.strip())
    L.append("```\n")

    L.append("## 8. 권고 및 조치\n")
    L.append((n.get("recommendation_ko") or "").strip() + "\n")
    L.append("> **위 차단 정책을 적용하시겠습니까?  [ o / x ]**\n")

    L.append("## 9. 커버리지 한계\n")
    L.append((a.get("assessment") or "시그니처 + 행동 휴리스틱 범위 내에서만 유효.").strip() + "\n")
    return "\n".join(L)


def main():
    if len(sys.argv) < 2:
        raise SystemExit("사용법: python3 llm/render_report.py <name>")
    name = sys.argv[1]
    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(ROOT, "reports", f"{name}.json"), encoding="utf-8") as f:
        report = json.load(f)
    rpath = os.path.join(ROOT, "reports", f"{name}.rules")
    rules_text = (open(rpath, encoding="utf-8").read() if os.path.exists(rpath)
                  else "# (차단 정책 없음 — make_policy.py 먼저 실행)")
    md = render(name, report, rules_text)
    out = os.path.join(ROOT, "reports", f"{name}.md")
    with open(out, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"[report] {out}  ({len(md)} chars)")


if __name__ == "__main__":
    main()
