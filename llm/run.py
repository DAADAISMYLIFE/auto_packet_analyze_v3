import sys, json

from tools import Tools
from ollama import chat

MODEL = "gemma4:26b"
MAX_TURNS = 12         # tool 루프 무한방지 (필수 섹션 다 조회 + 결론 낼 여유)
NUM_CTX = 16384        # 컨텍스트 크기 (tool 결과 누적 + 최종 답 잘림 방지)

SYSTEM_PROMPT = """\
# Role
You are a network forensics analyst in an automated pcap-analysis pipeline.
Suricata and Zeek have already processed the capture. Deterministically-extracted
Tier-1 facts (hosts, alerts, external contacts, files, lateral-movement signals)
are available through the tools below.

# Grounding rules (strict)
- Base every conclusion ONLY on tool-query results.
- NEVER invent IPs, domains, hashes, hostnames, or usernames. If a value is not in
  a tool result, do not output it.
- If something is unknown, say "unknown". Do not guess.
- Malware family names come from the alert 'signature' text. Do not attribute any
  malware that no signature or IOC supports.

# Tools
Call these to fetch the Tier-1 evidence, one section at a time:
- get_hosts_info() / get_host_info(ip)        : internal host identities
- get_alerts() / get_alerts_by_severity(sev)  : Suricata alerts (severity 1 = highest)
- get_external()                              : external IPs / domains / SNI (C2 / IOC)
- get_files()                                 : transferred files (malware candidates)
- get_lateral_movement()                      : internal-spread summary
Do not omit: before concluding, review the hosts, the severity-1 AND severity-2
alerts, the external contacts, the files, and the lateral-movement signals.

# Task
Grounded in the tool results, determine:
1. Victims / internal hosts: ip, mac, hostname, username, role.
2. Attacker endpoints & IOCs: external IPs, domains, file hashes.
3. Malware and attack behavior per host (download / C2 / lateral movement).
4. Infection chain as a time-ordered scenario (use the ts fields).
Report every item. If unknown, mark it "unknown" — never omit silently, never fabricate.

# Language
Reason in English. (The final human-facing report is produced later, in Korean.)
"""

def chatting(tools):
    # 채팅 기본 구조
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",
         "content": "Analyze this incident. Gather the Tier-1 evidence with the tools, "
                    "then report the victims, attacker/IOCs, malware per host, and the "
                    "infection timeline."},
    ]

    for _ in range(MAX_TURNS):
        res = chat(model=MODEL, messages=messages, tools=tools.TOOLS,
                   options={"num_ctx": NUM_CTX})

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