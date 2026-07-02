import sys, json

from tools import Tools
from ollama import chat

MODEL = "gemma4:26b"
MAX_TURNS = 12         # tool 루프 무한방지 (필수 섹션 다 조회 + 결론 낼 여유)
NUM_CTX = 16384        # 컨텍스트 크기 (tool 결과 누적 + 최종 답 잘림 방지)

SYSTEM_PROMPT = """\
# Role
You are a network forensics analyst in an automated pcap-analysis pipeline.
Suricata and Zeek have already processed the capture. The complete Tier-1 evidence
summary (hosts, alerts, external contacts, files, lateral-movement signals) is
ALREADY included in the first user message. Read it carefully before doing anything.

# Grounding rules (strict)
- Base every conclusion ONLY on the provided evidence and tool results.
- NEVER invent IPs, domains, hashes, hostnames, or usernames. If a value is not in
  the evidence or a tool result, do not output it.
- If something is unknown, say "unknown". Do not guess.
- Malware family names come from the alert 'signature' text. Do not attribute any
  malware that no signature or IOC supports.

# Tool discipline
The Tier-1 summary is already in front of you — NEVER call a tool to re-fetch it.
Tools exist only for narrow follow-up questions the summary cannot answer:
- get_host_info(ip)            : full detail of ONE host
- get_alerts_by_severity(sev)  : re-list alerts of one severity (1 = highest)
- search_external(keyword)     : find an external IP/domain/SNI dropped as background
Rules:
- Never repeat a call with the same arguments — results never change between calls.
- Each tool call costs budget. When you have enough evidence to answer, STOP calling
  tools and write the report.
- If a message tells you the tool budget is exhausted, do not request tools again;
  produce the final report immediately from what you have.

# Task
Grounded in the evidence, determine:
1. Victims / internal hosts: ip, mac, hostname, username, role.
   (Infrastructure such as a domain controller, gateway, or DNS server is not a
   "victim" unless the evidence shows it was itself compromised.)
2. Attacker endpoints & IOCs: external IPs, domains, file hashes.
3. Malware and attack behavior per host (download / C2 / lateral movement).
4. Infection chain as a time-ordered scenario (use the ts fields; identify which
   host was infected FIRST).
Report every item. If unknown, mark it "unknown" — never omit silently, never fabricate.

# Output


# Language
Reason in English. (The final human-facing report is produced later, in Korean.)
"""

def chatting(tools):
    # tier1 정보 주입
    tier1_evidence = json.dumps({
        "hosts": tools.get_hosts_info(),
        "alerts" : tools.get_alerts(),
        "external" : tools.get_external(),
        "files" : tools.get_files(),
        "lateral_movement" : tools.get_lateral_movement(),
        "anomalies" : tools.get_anomalies()
    }, ensure_ascii=False, default=str)



    # 채팅 기본 구조
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",
         "content": "Analyze this incident. The Tier-1 evidence is below. Use the drill-down "
                    "tools only for follow-up questions, then report the victims, attacker/IOCs, "
                    "malware per host, and the infection timeline.\n\n# Tier-1 Evidence\n" + tier1_evidence},
    ]

    for _ in range(MAX_TURNS):
        res = chat(model=MODEL, messages=messages, tools=tools.TOOLS,
                   options={"temperature":0.3, "seed": 42 ,"num_ctx": NUM_CTX})

        # tool 을 안 부르면 그게 최종 답
        if not res.message.tool_calls:
            print(res.message.content)
            return res.message.content
    
        # 모델의 tool_call 기록 누적
        messages.append(res.message)
        for tc in res.message.tool_calls:
            name = tc.function.name
            fn = tools.AVAILABLE.get(name)
            result = fn(**tc.function.arguments) if fn else {"error": f"unknown tool: {name}"}
            print(f"[tool] {name}({dict(tc.function.arguments)})")
            # 결과를 role:tool 로 주입 → 다음 chat 에서 모델이 보고 이어감
            messages.append({"role": "tool", "tool_name": name,
                             "content": json.dumps(result, ensure_ascii=False, default=str)})

    print("(max turns reached)")

def main():
    # 1. 매개변수로 어떤 evidence파일인지 입력 받기
    filename = sys.argv[1]
    
    # 2. TOOLS 클래스 생성 
    tools = Tools(filename)

    # 3. 응답 요청
    chatting(tools)

if __name__ == "__main__":
    main()