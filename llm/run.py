import sys, json, re, os

from tools import Tools
from ollama import chat
from config import (MODEL, OPTS, VERDICT_SCHEMA, REPORT_SCHEMA,
                    SYSTEM_PROMPT_TRIAGE, SYSTEM_PROMPT_FORENSIC)

def triage(tools):
    tier1_evidence = json.dumps({
        "meta": tools.get_meta(),
        "hosts": tools.get_hosts_info(),
        "alerts" : tools.get_alerts(),
        "external" : tools.get_external(),
        "files" : tools.get_files(),
        "lateral_movement" : tools.get_lateral_movement(),
        "anomalies" : tools.get_anomalies()
    }, ensure_ascii=False, default=str)

    res = chat(model=MODEL, format=VERDICT_SCHEMA,   # ← format이 강제 선택
            think=False,                              # thinking 끔: content가 바로 JSON, 추론토큰이 예산 안 먹음
            messages=[{"role": "system", "content": SYSTEM_PROMPT_TRIAGE},
                        {"role": "user", "content": "Triage this capture.\n\n# Tier-1 Evidence\n" + tier1_evidence}],
            options=OPTS
            )

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
        print("[triage] verdict 복구 실패 — suspicious 폴백")
        print("  content(repr):", repr(content[:200]))   # 비었나/뭐가왔나 진단용
        print("  thinking 있었나:", bool(getattr(res.message, "thinking", None)))
        return {"verdict": "suspicious",
                "grounds": ["triage 출력 파싱 실패 — 안전을 위해 분석 단계로 에스컬레이트"]}

def forensic(tools):
    # tier1 정보 주입 (claude_llm 검증: tier1 만으로 충분 → tool 루프 없이 단일 호출)
    tier1_evidence = json.dumps({
        "meta": tools.get_meta(),
        "hosts": tools.get_hosts_info(),
        "alerts" : tools.get_alerts(),
        "external" : tools.get_external(),
        "files" : tools.get_files(),
        "lateral_movement" : tools.get_lateral_movement(),
        "anomalies" : tools.get_anomalies()
    }, ensure_ascii=False, default=str)

    # format 강제 → 마크다운 산문이 아니라 REPORT_SCHEMA JSON 을 그대로 받는다
    res = chat(model=MODEL, format=REPORT_SCHEMA, think=False,
               messages=[{"role": "system", "content": SYSTEM_PROMPT_FORENSIC},
                         {"role": "user",
                          "content": "Analyze this incident and return the structured JSON."
                                     "\n\n# Tier-1 Evidence\n" + tier1_evidence}],
               options=OPTS)
    try:
        return json.loads(res.message.content)
    except (json.JSONDecodeError, TypeError):
        print("[forensic] 구조화 JSON 파싱 실패 — content(repr):",
              repr((res.message.content or "")[:300]))
        return None

def attach_mac(analysis, tools):
    """victims[].mac 을 evidence 의 ip 조인 값으로 교정/부착.

    mac 은 LLM 도 출력하지만(스키마에 있음), 베끼다 손상되는 사고
    (CFA3467 류 hostname 오염과 같은 클래스)가 있어 코드가 정답으로 덮어쓴다.
    ip 가 evidence 에 없으면 None (환각 mac 도 이때 제거됨).
    """
    by_ip = {h.get("ip"): h.get("mac") for h in tools.evidence.get("hosts", [])}
    for v in analysis.get("victims", []):
        v["mac"] = by_ip.get(v.get("ip"))

def attach_hashes(analysis, tools):
    """iocs.hashes 를 evidence 의 malware-candidate 파일에서 코드가 채운다 (해시 블라인드니스 방지).

    LLM 은 files[] 를 보고도 hashes 를 거의 항상 [] 로 낸다 → 코드가 확정값으로 덮어쓴다.
    ms-pol(정상 GPO) + 업데이트 인프라(windowsupdate 등)가 서빙한 x-dosexec 은 serving-host
    조인으로 제외한다 (MS Defender 업데이트 해시를 차단정책에 넣던 오탐 차단).
    제외분은 침묵하지 않고 _excluded_benign_hashes 로 노출(투명).
    """
    res = tools.malware_candidate_hashes()
    analysis.setdefault("iocs", {})["hashes"] = res["malware"]
    if res["benign_excluded"]:
        analysis["_excluded_benign_hashes"] = res["benign_excluded"]

def ground_iocs(analysis, tools):
    """iocs 의 IP/도메인을 evidence 관측집합과 exact-match 대조해 오염/환각을 제거한다.
    (차단정책 안전장치 — 오염된 IP 로 깨진 Snort 룰이 나가는 것을 원천 차단.)

    - 복원은 안 함: '1para.36.191.35' 를 '194.36.191.35' 로 추측하지 않는다(추측이
      틀리면 정상 서버 차단 위험). evidence 에 없으면 그냥 제거.
    - 도메인은 suffix 허용: 'mail.staroxalate.com' 은 'staroxalate.com' 관측으로 인정.
    - 제거분은 조용히 버리지 않고 _rejected_iocs 로 노출(사람 검토용).
    - hashes 는 이미 attach_hashes 가 evidence 에서 코드로 채우므로 건드리지 않는다.
    """
    obs = tools.observed_iocs()

    def dom_ok(d):
        d = d.lower()
        return any(d == o or d.endswith("." + o) or o.endswith("." + d) for o in obs["domains"])

    iocs = analysis.get("iocs", {})
    rejected = []
    for bucket in ("c2", "delivery", "exfil"):
        kept = []
        for ip in iocs.get(bucket, []):
            if str(ip).lower() in obs["ips"]:
                kept.append(ip)
            else:
                rejected.append({"kind": "ip", "bucket": bucket, "value": ip,
                                 "reason": "evidence 미관측 (오염/환각)"})
        iocs[bucket] = kept
    kept_doms = []
    for d in iocs.get("domains", []):
        if dom_ok(str(d)):
            kept_doms.append(d)
        else:
            rejected.append({"kind": "domain", "value": d,
                             "reason": "evidence 미관측 (오염/환각)"})
    iocs["domains"] = kept_doms
    if rejected:
        analysis["_rejected_iocs"] = rejected

def main():
    # 1. 매개변수로 어떤 evidence파일인지 입력 받기
    if len(sys.argv) < 2:
        raise SystemExit("사용법: python3 run.py <output/ 아래 evidence 폴더명>")
    filename = sys.argv[1]

    # 2. TOOLS 클래스 생성
    tools = Tools(filename)

    # 3. triage → (에스컬레이션 시) forensic. 모든 결과를 하나의 JSON 으로.
    res = triage(tools)
    out = {"verdict": res["verdict"], "grounds": res.get("grounds", [])}

    if res["verdict"] == "no_incident":
        # 무혐의: 분석 chat 안 감 (사건 전제 프레이밍 차단)
        print("=== 판정: 이상 없음 ===")
        for g in out["grounds"]:
            print(f"  - {g}")
        print("잔여 리스크: 본 판정은 시그니처+행동 휴리스틱 커버리지 내에서만 유효함.")
    else:
        analysis = forensic(tools)
        if analysis:
            attach_mac(analysis, tools)
            attach_hashes(analysis, tools)
            ground_iocs(analysis, tools)       # iocs 오염/환각 제거 (차단정책 안전장치)
            out["analysis"] = analysis
            print(json.dumps(analysis, ensure_ascii=False, indent=2))
        else:
            print("[main] 분석 JSON 생성 실패 — verdict 만 저장")

    # 4. JSON 저장 (채점/렌더링 공통 입력)
    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    outdir = os.path.join(ROOT, "reports")
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, f"{filename}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"[report] 저장됨 → {path}")

if __name__ == "__main__":
    main()
