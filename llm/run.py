import sys, json, re

from tools import Tools
from validate import check_iocs, format_findings
from ollama import chat

MODEL = "gemma4:26b"
MAX_TURNS = 12         # tool 루프 무한방지 (필수 섹션 다 조회 + 결론 낼 여유)
NUM_CTX = 24576        # 컨텍스트 크기 (tier1 주입 + tool 결과 누적 + 보고서까지 여유)

VERDICT_SCHEMA = {
    "type" : "object",
    "properties": {
        "verdict": {"enum": ["no_incident", "suspicious", "confirmed"]},
        "grounds": {"type": "array", "items": {"type": "string"},
                    "maxItems": 6,
                    "description": "specific evidence values that drove the verdict"},
    },
    "required" : ["verdict","grounds"]
}

SYSTEM_PROMPT_TRIAGE = """\
# Role
You are the TRIAGE stage of an automated pcap-analysis pipeline. Your ONLY job is
to decide whether this capture contains evidence of a security incident. You do
NOT write a report. A separate stage performs deep analysis ONLY if you escalate.

# How to weigh the evidence
1. alerts       — threat signatures. (capture_diagnostics are NOT threats — they
                  are capture artifacts such as NIC checksum offloading.)
2. files        — malware-candidate transfers.
3. anomalies    — signature-less measurements. Raw numbers, not verdicts. Judge
                  with context:
                  - ABSOLUTE volume matters: a high upload ratio on a few KB is
                    normal client traffic, not exfiltration.
                  - a short capture (see meta/duration) makes beacon and DNS
                    heuristics unreliable.
                  - well-known cloud/CDN/NTP endpoints are usually background.
4. lateral_movement — routine AD traffic toward infrastructure (DC/DNS/DHCP)
                  is normal, not an attack.

# Verdict rules
- no_incident: no threat alerts, no malware-candidate files, and every anomaly has
  a mundane explanation. For clean traffic this is the EXPECTED verdict — absence
  of findings is a valid, correct result. Do NOT invent threats to fill sections.
- suspicious: no signature hits, but at least one behavioral signal lacks an
  innocent explanation (sustained low-jitter beaconing, workstation SMTP burst,
  large-volume upload to a first-seen endpoint, high-entropy DNS at scale).
- confirmed: threat-signature alerts and/or malware-candidate files, corroborated
  by behavior.

Quote evidence values in grounds exactly as written — never re-type from memory.

# Examples (illustrative values only — NOT from this capture)
Input (excerpt):
  {"meta": {"duration_s": 15.0}, "alerts": [], "files": [],
   "anomalies": {"beacons": [],
                 "exfil_candidates": [{"dst": "203.0.113.7", "bytes_out": 15200,
                                       "bytes_in": 600, "ratio": 25.3}]}}
Output:
  {"verdict": "no_incident",
   "grounds": ["no threat alerts and no malware-candidate files",
               "upload ratio 25.3 to 203.0.113.7 is only 15200 bytes total — normal client traffic, not exfiltration",
               "capture duration 15.0s is too short for beacon/DNS heuristics"]}

Input (excerpt):
  {"alerts": [],
   "anomalies": {"role_deviation": [{"src": "192.0.2.10", "service": "smtp",
                                     "conns": 180, "distinct_dsts": 70}]}}
Output:
  {"verdict": "suspicious",
   "grounds": ["workstation 192.0.2.10 initiated smtp to 70 distinct external hosts (180 conns) — spam-module behavior with no innocent explanation in the evidence"]}

Input (excerpt):
  {"alerts": [{"signature": "ET MALWARE Example RAT CnC Checkin", "severity": 1,
               "count": 12, "dst_ips": ["198.51.100.9"]}],
   "files": [{"mime": "application/x-dosexec", "sha256": "ab12cd34..."}]}
Output:
  {"verdict": "confirmed",
   "grounds": ["severity-1 alert 'ET MALWARE Example RAT CnC Checkin' fired 12 times toward 198.51.100.9",
               "executable transfer (application/x-dosexec, sha256 ab12cd34...) corroborates infection"]}
"""

SYSTEM_PROMPT = """\
# Role
You are a network forensics analyst in an automated pcap-analysis pipeline.
Suricata and Zeek have already processed the capture. The complete Tier-1 evidence
summary (hosts, alerts, external contacts, files, lateral-movement signals, and
signature-less behavioral measurements in `anomalies`) is ALREADY included in the
first user message. Read it carefully before doing anything. A triage stage has
already judged this capture worth analyzing.

# Grounding rules (strict)
- Base every conclusion ONLY on the provided evidence and tool results.
- NEVER invent IPs, domains, hashes, hostnames, or usernames. If a value is not in
  the evidence or a tool result, do not output it. Copy values exactly — never
  re-type from memory.
- If something is unknown, say "unknown". Do not guess.
- Malware family names come from the alert 'signature' text. Do not attribute any
  malware that no signature or IOC supports.

# Independent infections vs. lateral movement
- Default to INDEPENDENT infections. Multiple internal hosts each contacting
  their OWN external C2 are separate incidents, NOT one spreading chain. If there
  is no direct evidence linking them, report them as independent.
- Internal host -> DC / DNS / DHCP over SMB / NTLM / Kerberos / LDAP is normal
  Active Directory authentication. NEVER call this lateral movement on its own.
- Only describe lateral movement when a compromised host directly attacks ANOTHER
  WORKSTATION over an admin channel (e.g. SMB write to ADMIN$/C$, remote service
  creation via svcctl, scheduled task via atsvc, DCSync via drsuapi).
- PROBE vs EXECUTION — read the dcerpc_ops in lateral_movement literally:
  `OpenSCManager2` / `ept_map` / share=PIPE with smb_writes=0 is a PROBE or
  enumeration attempt, NOT successful lateral movement. Escalate to actual
  lateral movement ONLY when you see `CreateServiceW`/`StartServiceW`,
  `SchRpcRegister`/`NetrJobAdd`, `DsGetNCChanges`, or a non-zero smb_writes to an
  admin share. If only probe-level ops with zero writes are present, say
  "probing attempt, no evidence of execution" and keep the hosts independent.
- If you cannot tell whether hosts are linked, treat them as independent and mark
  the relationship "unknown". Do not invent a chain to make the story cohere.

# Exfiltration judgement
- Judge outbound uploads by CONTEXT, not byte volume. A high upload ratio is not
  exfiltration by itself. Weigh: is the destination a first-seen / no-DNS /
  low-reputation endpoint, and did this host have a prior malicious signal? A
  well-known cloud/CDN/SaaS destination with no prior signal is background.

# Attribution caution
- A JA3 "possible/abuse.ch" match is a POSSIBILITY, not a confirmed family. Report
  it as "possible X (JA3 match)", never as a definite attribution.

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
Address every `anomalies` entry: either connect it to the incident or dismiss it
with a stated reason. Report every item. If unknown, mark it "unknown" — never
omit silently, never fabricate.

# Language
Reason in English. (The final human-facing report is produced later, in Korean.)
"""

def triage(tools):
    tier1_evidence = json.dumps({
        "hosts": tools.get_hosts_info(),
        "alerts" : tools.get_alerts(),
        "external" : tools.get_external(),
        "files" : tools.get_files(),
        "lateral_movement" : tools.get_lateral_movement(),
        "anomalies" : tools.get_anomalies()
    }, ensure_ascii=False, default=str)

    res = chat(model=MODEL, format=VERDICT_SCHEMA,   # ← format이 강제 선택
            messages=[{"role": "system", "content": SYSTEM_PROMPT_TRIAGE},
                        {"role": "user", "content": "Triage this capture.\n\n# Tier-1 Evidence\n" + tier1_evidence}],
            # num_predict: verdict+grounds 6개면 충분. 문법강제 반복루프가 nc_ctx까지
            #   폭주하는 걸 물리적으로 캡 → 잘려도 아래 try/except 가 suspicious 로 받음.
            # repeat_penalty: 문법강제 하 grounds 배열 반복루프 억제
            options={"temperature": 0.3, "seed": 42, "num_ctx": NUM_CTX,
                     "num_predict": 400, "repeat_penalty": 1.3})

    content = res.message.content
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # grounds 폭주로 JSON 이 잘려도 verdict 는 맨 앞이라 살아있음 → 정규식으로 복구
        m = re.search(r'"verdict"\s*:\s*"(no_incident|suspicious|confirmed)"', content)
        if m:
            print(f"[triage] JSON 잘림 — verdict 복구: {m.group(1)}")
            return {"verdict": m.group(1),
                    "grounds": ["(grounds 폭주로 잘림 — verdict 만 복구)"]}
        print("[triage] verdict 복구 실패 — suspicious 폴백 (원문 앞부분):")
        print(content[:300])
        return {"verdict": "suspicious",
                "grounds": ["triage 출력 파싱 실패 — 안전을 위해 분석 단계로 에스컬레이트"]}

def forensic(tools):
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
    res = triage(tools)

    if res["verdict"] == "no_incident":
        # 무혐의: 분석 chat 안 감 (사건 전제 프레이밍 차단)
        print("=== 판정: 이상 없음 ===")
        print("근거:")
        for g in res["grounds"]:
            print(f"  - {g}")
        print("잔여 리스크: 본 판정은 시그니처+행동 휴리스틱 커버리지 내에서만 유효함.")
        return

    report = forensic(tools)

    # 4. IOC 검증 게이트: 보고서의 IP/도메인/해시를 evidence 와 대조 (오염·환각 차단)
    if report:
        print()
        print(format_findings(check_iocs(report, tools.evidence)))

if __name__ == "__main__":
    main()