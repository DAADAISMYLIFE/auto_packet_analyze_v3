#!/usr/bin/env python3
"""가드(코드 소유 후처리) 유닛테스트 — LLM/GPU/pcap 없이 1초 안에 돈다.

왜: 가드는 이 레포에서 제일 정교한 문자열 수술(옥텟 재조립·장식 벗기기·버킷 이관·suffix 매칭)인데
검증 수단이 전체 파이프라인 e2e 뿐이었다. e2e 는 모델 비결정성과 섞여 "가드가 깨졌나 / 모델이
오늘 이상한가"를 구분 못 한다. 여기선 'LLM 이 이렇게 망친 답을 줬다 치자'를 dict 로 만들어
가드가 제대로 고치는지만 본다.

실행:  cd llm && python3 test_guards.py        (pytest 있으면 pytest test_guards.py 도 됨)
노트북(Kaggle)은 파이프라인 전에 이걸 돌려 빨간불이면 멈춘다.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tools import Tools
import run
from run import (CaseContext, PASSES, apply_guards, attach_identity, demote_infra_victims,
                 attach_hashes, ground_iocs, annotate_attacks, attach_iocs_from_alerts,
                 attach_iocs_from_dns, attach_inbound_threat_ips, _is_threat_alert)


# ─────────────────────────── 픽스처 ───────────────────────────
class FakeTools(Tools):
    """evidence 를 파일이 아니라 dict 로 받는 Tools. observed_iocs 등은 진짜 구현을 그대로 탄다."""
    def __init__(self, evidence, malware=None, benign=None):
        self.evidence = evidence
        self._mal, self._ben = malware or [], benign or []

    def malware_candidate_hashes(self):           # zeek 로그 조인 없이 결과만 주입
        return {"malware": self._mal, "benign_excluded": self._ben}


def ev(hosts=None, ext_ips=(), domains=None, sni=(), alerts=None, files=None):
    """최소 evidence. hosts=[(ip, role, extra)] / domains=[(query, [answers])]."""
    return {
        "hosts": [dict({"ip": ip, "role": role, "mac": f"aa:{i}", "hostname": f"h{i}",
                        "username": f"u{i}"}, **(extra or {}))
                  for i, (ip, role, extra) in enumerate(hosts or [])],
        "external": {
            "ips": [{"ip": ip} for ip in ext_ips],
            "domains": [{"query": q, "answers": list(a)} for q, a in (domains or [])],
            "sni": [{"sni": s} for s in sni],
        },
        "alerts": alerts or [],
        "files": files or [],
    }


def alert(sig, src, dst, threat_class=None, severity=1):
    a = {"signature": sig, "severity": severity, "src_ips": list(src), "dst_ips": list(dst)}
    if threat_class is not None:
        a["threat_class"] = threat_class
    return a


def ctx_for(analysis, evidence, **kw):
    return CaseContext(analysis, FakeTools(evidence, **kw))


WS, DC = ("10.0.0.5", "workstation", None), ("10.0.0.2", "domain_controller", {"ad_domain": "corp.local"})


# ─────────────────────────── attach_identity ───────────────────────────
def test_identity_octet_reassembly_and_join():
    e = ev(hosts=[WS])
    a = {"victims": [{"ip": "10.0_0.5", "hostname": "CFA3467(오염)", "mac": "zz"}],
         "patient_zero": "10.0.0.5 (First observed at ...)"}
    attach_identity(a, ctx_for(a, e))
    v = a["victims"][0]
    assert v["ip"] == "10.0.0.5", v                      # 구분자 손상 복구 (호스트 대조로만)
    assert v["hostname"] == "h0" and v["mac"] == "aa:0"  # LLM 오염값을 evidence 로 덮어씀
    assert v["role"] == "workstation"
    assert a["patient_zero"] == "10.0.0.5"               # 장식 제거


def test_identity_no_guessing_for_unknown_ip():
    e = ev(hosts=[WS])
    a = {"victims": [{"ip": "10.0.0.99", "hostname": "ghost"}]}
    attach_identity(a, ctx_for(a, e))
    v = a["victims"][0]
    assert v["ip"] == "10.0.0.99"                         # 호스트가 아니면 원문 유지(추측 금지)
    assert v["hostname"] is None and v["mac"] is None    # 정체는 환각 제거 → None


# ─────────────────────────── attach_hashes ───────────────────────────
def test_hashes_filled_by_code_and_benign_exposed():
    a = {"iocs": {"hashes": []}}
    c = ctx_for(a, ev(), malware=["a" * 64], benign=[{"sha256": "b" * 64, "serving_host": "x.windowsupdate.com"}])
    attach_hashes(a, c)
    assert a["iocs"]["hashes"] == ["a" * 64]
    assert a["_excluded_benign_hashes"][0]["serving_host"].endswith("windowsupdate.com")


# ─────────────────────────── ground_iocs ───────────────────────────
def test_ground_removes_unobserved_keeps_observed_strips_decoration():
    e = ev(hosts=[WS], ext_ips=["1.2.3.4"])
    a = {"iocs": {"c2": ["1.2.3.4 (HTTP Beacon)", "9.9.9.9"], "delivery": [], "exfil": [], "domains": []}}
    ground_iocs(a, ctx_for(a, e))
    assert a["iocs"]["c2"] == ["1.2.3.4"]
    assert [r["value"] for r in a["_rejected_iocs"]] == ["9.9.9.9"]
    assert "환각" in a["_rejected_iocs"][0]["reason"]


def test_ground_salvages_domain_misplaced_in_ip_bucket():
    e = ev(hosts=[WS], ext_ips=["1.2.3.4"], domains=[("evil.com", ["1.2.3.4"])])
    a = {"iocs": {"c2": ["http://evil.com/gate.php"], "delivery": [], "exfil": [], "domains": []}}
    ground_iocs(a, ctx_for(a, e))
    assert a["iocs"]["c2"] == []
    assert a["iocs"]["domains"] == ["evil.com"]           # IP 버킷 → domains 이관


def test_ground_rejects_internal_assets_ip_and_ad_zone():
    e = ev(hosts=[WS, DC], ext_ips=["1.2.3.4"], domains=[("evil.com", ["1.2.3.4"])])
    a = {"iocs": {"c2": ["10.0.0.2"], "delivery": [], "exfil": [],
                  "domains": ["dc1.corp.local", "corp.local", "evil.com"]}}
    ground_iocs(a, ctx_for(a, e))
    assert a["iocs"]["c2"] == []
    assert a["iocs"]["domains"] == ["evil.com"]
    reasons = {r["value"]: r["reason"] for r in a["_rejected_iocs"]}
    assert "내부 자산" in reasons["10.0.0.2"] and "내부 자산" in reasons["dc1.corp.local"]


def test_ground_domain_suffix_ok_but_tld_floor_blocks():
    e = ev(hosts=[WS], domains=[("mail.evil.com", ["1.2.3.4"]), ("x.co.kr", ["5.6.7.8"])])
    a = {"iocs": {"c2": [], "delivery": [], "exfil": [],
                  "domains": ["evil.com", "com", "co.kr", "mail.evil.com"]}}
    ground_iocs(a, ctx_for(a, e))
    assert a["iocs"]["domains"] == ["evil.com", "mail.evil.com"]   # 부모 인정, TLD/공용접미사 기각, 중복 제거
    rejected = {r["value"] for r in a["_rejected_iocs"]}
    assert rejected == {"com", "co.kr"}


# ─────────────────────────── annotate_attacks ───────────────────────────
def test_annotate_scopes_and_removes_targets_from_iocs():
    e = ev(hosts=[WS], ext_ips=["8.8.4.4"])
    a = {"attacks": [{"actor": "203.0.113.9", "target": "10.0.0.5"},
                     {"actor": "10.0.0.5", "target": "8.8.4.4", "target_host": "victim.example",
                      "sample_uri": "victim.example/wp-login.php"}],
         "iocs": {"c2": ["8.8.4.4", "203.0.113.9"], "delivery": [], "exfil": [],
                  "domains": ["victim.example", "evil.com"]}}
    annotate_attacks(a, ctx_for(a, e))
    assert a["attacks"][0]["actor_scope"] == "external" and a["attacks"][0]["target_scope"] == "internal"
    assert a["attacks"][1]["actor_scope"] == "internal"
    assert a["iocs"]["c2"] == ["203.0.113.9"]              # 표적 8.8.4.4 제거, 공격자 보존
    assert a["iocs"]["domains"] == ["evil.com"]            # 표적 호스트 제거
    assert len(a["_removed_attack_targets"]) == 2


# ─────────────────────────── attach_iocs_from_alerts (카테고리 게이트) ───────────────────────────
def test_alerts_gate_uses_threat_class_not_severity():
    e = ev(hosts=[WS], ext_ips=["108.160.1.1", "5.5.5.5"], alerts=[
        alert("ET FILE_SHARING Dropbox", ["10.0.0.5"], ["108.160.1.1"], "benign", severity=1),
        alert("ET MALWARE Poweliks CnC", ["10.0.0.5"], ["5.5.5.5"], "threat", severity=1),
    ])
    a = {"iocs": {"c2": [], "delivery": [], "exfil": [], "domains": []}}
    attach_iocs_from_alerts(a, ctx_for(a, e))
    assert a["iocs"]["c2"] == ["5.5.5.5"]                  # Dropbox sev1 은 승격 안 됨
    assert a["_iocs_added_from_alerts"] == ["5.5.5.5"]


def test_alerts_gate_legacy_evidence_falls_back_to_regex():
    # threat_class 필드가 없는 구 evidence → 시그니처 정규식 폴백 (동일 결과)
    e = ev(hosts=[WS], ext_ips=["108.160.1.1", "5.5.5.5"], alerts=[
        alert("ET CHAT Skype", ["10.0.0.5"], ["108.160.1.1"]),
        alert("ET TROJAN Zeus Checkin", ["10.0.0.5"], ["5.5.5.5"]),
    ])
    assert not _is_threat_alert(e["alerts"][0]) and _is_threat_alert(e["alerts"][1])
    a = {"iocs": {"c2": [], "delivery": [], "exfil": [], "domains": []}}
    attach_iocs_from_alerts(a, ctx_for(a, e))
    assert a["iocs"]["c2"] == ["5.5.5.5"]


def test_alerts_excludes_attack_targets_and_dedups():
    # 표적 제외는 '공격 카테고리(WEB_SERVER 등)' alert 의 dst 에만 적용된다 — 멀웨어-통신
    # (MALWARE/CNC) alert 의 dst 는 C2 라서 표적 오기여도 보호됨(test_c2_mislabeled... 참조).
    e = ev(hosts=[WS], ext_ips=["5.5.5.5", "6.6.6.6"], alerts=[
        alert("ET MALWARE X", ["10.0.0.5"], ["5.5.5.5"], "threat"),
        alert("ET WEB_SERVER SQL Injection", ["10.0.0.5"], ["6.6.6.6"], "threat")])
    a = {"attacks": [{"actor": "10.0.0.5", "target": "6.6.6.6"}],
         "iocs": {"c2": [], "delivery": ["5.5.5.5"], "exfil": [], "domains": []}}
    attach_iocs_from_alerts(a, ctx_for(a, e))
    assert a["iocs"]["c2"] == []                            # 6.6.6.6=피격자 제외 유지, 5.5.5.5 는 delivery 에 이미 있음
    assert "_iocs_added_from_alerts" not in a


# ─────────────────────────── attach_iocs_from_dns ───────────────────────────
def test_dns_promotes_suspicious_tld_resolving_to_contacted_ip():
    e = ev(hosts=[WS, DC], ext_ips=["46.1.1.1"], domains=[
        ("abc.yjug.gq", ["46.1.1.1"]),          # 의심 TLD + 실제 접속 IP → 승격
        ("zzz.evil.xyz", ["7.7.7.7"]),          # 의심 TLD 지만 접속 안 함 → 승격 안 함
        ("www.google.com", ["46.1.1.1"]),       # 정상 TLD → 승격 안 함
        ("svc.corp.local", ["46.1.1.1"]),       # AD 존 → 제외
    ])
    a = {"iocs": {"c2": [], "delivery": [], "exfil": [], "domains": []}}
    attach_iocs_from_dns(a, ctx_for(a, e))
    assert a["iocs"]["domains"] == ["abc.yjug.gq"]
    assert a["iocs"]["c2"] == ["46.1.1.1"]


# ─────────────────────────── attach_inbound_threat_ips ───────────────────────────
def test_inbound_promotes_external_attacker_only_for_threat_alerts():
    e = ev(hosts=[("192.168.0.2", "server", None)], ext_ips=[], alerts=[
        alert("ET WEB_SERVER CVE-2014-6271 Attempt", ["146.52.78.242"], ["192.168.0.2"], "threat"),
        alert("ET CHAT Skype", ["1.1.1.1"], ["192.168.0.2"], "benign"),            # benign 인바운드
        alert("ET MALWARE Outbound C2", ["192.168.0.2"], ["9.9.9.9"], "threat"),    # 아웃바운드(방향 게이트)
    ])
    a = {"iocs": {"c2": [], "delivery": [], "exfil": [], "domains": []}}
    attach_inbound_threat_ips(a, ctx_for(a, e))
    assert a["iocs"]["c2"] == ["146.52.78.242"]
    assert a["_iocs_added_inbound"] == ["146.52.78.242"]


# ─────────────────────────── demote_infra_victims ───────────────────────────
def test_demote_dc_receiving_auth_but_keep_dc_originating_threat():
    e = ev(hosts=[WS, DC, ("10.0.0.3", "domain_controller", None)], ext_ips=["5.5.5.5"], alerts=[
        alert("ET MALWARE Beacon", ["10.0.0.3"], ["5.5.5.5"], "threat")])   # DC2 가 외부로 악성 통신
    a = {"victims": [{"ip": "10.0.0.2", "role": "domain_controller", "status": "compromised", "malware": ["X"]},
                     {"ip": "10.0.0.3", "role": "domain_controller", "status": "compromised", "malware": ["Y"]},
                     {"ip": "10.0.0.5", "role": "workstation", "status": "compromised", "malware": ["Z"]}]}
    demote_infra_victims(a, ctx_for(a, e))
    st = {v["ip"]: v["status"] for v in a["victims"]}
    assert st == {"10.0.0.2": "infrastructure", "10.0.0.3": "compromised", "10.0.0.5": "compromised"}
    assert a["_demoted_infra"] == ["10.0.0.2"]


# ─────────────────────────── PASSES 구조 + e2e(코드부만) ───────────────────────────
def test_passes_promoters_run_after_removers():
    idx = {f.__name__: i for i, f in enumerate(PASSES)}
    for remover in ("ground_iocs", "annotate_attacks"):
        for promoter in ("attach_iocs_from_alerts", "attach_iocs_from_dns", "attach_inbound_threat_ips"):
            assert idx[remover] < idx[promoter], f"{promoter} 가 {remover} 앞에 있음 — 승격분이 도로 지워진다"
    assert idx["attach_identity"] < idx["demote_infra_victims"]   # role 확정 뒤에 인프라 판정


def test_apply_guards_q2_shape_regression():
    """q2 실측 모양: LLM 이 광고/구글/페북/환각을 섞어 냈을 때 코드부가 뭘 남기는지 고정."""
    e = ev(hosts=[("192.168.0.53", "workstation", None), ("192.168.0.2", "server", None)],
           ext_ips=["88.214.241.199", "31.13.64.1", "46.108.156.146", "108.160.1.1"],
           domains=[("www.facebook.com", ["31.13.64.1"]), ("uugzv.yjuggczkkq.gq", ["46.108.156.146"]),
                    ("ad.doubleclick.net", ["1.1.1.1"])],
           alerts=[alert("ET MALWARE Poweliks Clickfraud CnC M4", ["192.168.0.53"], ["88.214.241.199"], "threat"),
                   alert("ET FILE_SHARING Dropbox", ["192.168.0.53"], ["108.160.1.1"], "benign"),
                   alert("ET WEB_SERVER Possible CVE-2014-6271", ["60.250.33.201"], ["192.168.0.2"], "threat")])
    a = {"victims": [{"ip": "192.168.0.53", "status": "compromised", "malware": ["Poweliks"]}],
         "attacks": [{"actor": "60.250.33.201", "target": "192.168.0.2"}],
         "iocs": {"c2": ["88.214.241.199", "192.168.0.2", "9.9.9.9"], "delivery": [],
                  "exfil": ["31.13.64.1"], "domains": ["ad.doubleclick.net"], "hashes": []}}
    apply_guards(a, FakeTools(e))
    assert a["iocs"]["c2"] == ["88.214.241.199", "46.108.156.146", "60.250.33.201"]   # 진짜 C2 + 터널IP + 인바운드 공격자
    assert "108.160.1.1" not in a["iocs"]["c2"]                                         # Dropbox sev1 미승격
    assert a["iocs"]["domains"] == ["ad.doubleclick.net", "uugzv.yjuggczkkq.gq"]
    # 한계를 정직하게 고정: 관측된 광고 도메인·페북 exfil 은 그라운딩이 '존재'만 보므로 코드부는 못 거른다
    # → 이건 프롬프트(threat_class/baseline 지시) + 향후 precision 채점의 몫. 이 assert 가 깨지면 개선된 것.
    assert a["iocs"]["exfil"] == ["31.13.64.1"]
    assert {r["value"] for r in a["_rejected_iocs"]} == {"192.168.0.2", "9.9.9.9"}
    assert a["victims"][0]["hostname"] == "h0" and a["attacks"][0]["actor_scope"] == "external"


# ─────────────────────────── 러너 (pytest 없이) ───────────────────────────
# ─────────────── C2 표적-보호 예외 + 코드 triage/승급 ───────────────
def test_c2_mislabeled_as_target_survives():
    """LLM 이 C2 통신을 attacks[].target 에 적어도, 멀웨어-통신 alert 가 가리키는 IP 는
    표적 제거에 안 지워지고 승격기가 c2 로 보장한다 (2024-07-30 STRRAT 실전 결함 회귀)."""
    e = ev(hosts=[WS], ext_ips=["5.252.153.241"],
           alerts=[alert("ET MALWARE Fake Microsoft Teams CnC Payload Request (GET)",
                         ["10.0.0.5"], ["5.252.153.241"], "threat")])
    a = {"victims": [], "attacks": [{"actor": "10.0.0.5", "target": "5.252.153.241"}],
         "iocs": {"c2": ["5.252.153.241"], "delivery": [], "exfil": [], "domains": [], "hashes": []}}
    run.apply_guards(a, FakeTools(e))
    assert "5.252.153.241" in a["iocs"]["c2"], a
    assert a.get("_c2_kept_despite_target_label") == ["5.252.153.241"]
    assert not any(r["value"] == "5.252.153.241" for r in a.get("_removed_attack_targets", []))


def test_real_outbound_attack_victim_still_removed():
    """자폭 방지 원칙 유지: WEB_SERVER 류 alert 의 dst(진짜 피격자)는 여전히 표적으로 제거되고
    승격기도 되살리지 않는다."""
    e = ev(hosts=[WS], ext_ips=["203.0.113.9"],
           alerts=[alert("ET WEB_SERVER Possible SQL Injection", ["10.0.0.5"], ["203.0.113.9"], "threat")])
    a = {"victims": [], "attacks": [{"actor": "10.0.0.5", "target": "203.0.113.9"}],
         "iocs": {"c2": ["203.0.113.9"], "delivery": [], "exfil": [], "domains": [], "hashes": []}}
    run.apply_guards(a, FakeTools(e))
    assert a["iocs"]["c2"] == [], a


def test_code_triage_skips_llm_on_threat_signal():
    e = ev(hosts=[WS], alerts=[alert("ET MALWARE Zeus Checkin", ["10.0.0.5"], ["9.9.9.9"], "threat")])
    r = run.code_triage(FakeTools(e))
    assert r and r["verdict"] == "suspicious" and "생략" in r["grounds"][0]


def test_code_triage_defers_quiet_capture_to_llm():
    e = ev(hosts=[WS], alerts=[alert("ET CHAT Skype", ["10.0.0.5"], ["9.9.9.9"], "benign")])
    assert run.code_triage(FakeTools(e)) is None    # benign 뿐이면 LLM 판단으로


def test_upgrade_verdict_deterministic():
    out = {"verdict": "suspicious", "grounds": []}
    run.upgrade_verdict(out, {"victims": [{"ip": "10.0.0.5", "status": "compromised"}],
                              "iocs": {"c2": ["9.9.9.9"]}})
    assert out["verdict"] == "confirmed" and "코드 승급" in out["grounds"][-1]
    out2 = {"verdict": "suspicious", "grounds": []}
    run.upgrade_verdict(out2, {"victims": [], "iocs": {"c2": ["9.9.9.9"]}})
    assert out2["verdict"] == "suspicious"          # 침해 확정 호스트 없으면 승급 안 함


def test_ground_iocs_accepts_http_host_only_domain():
    """DNS 질의 없이 직결+Host 헤더로만 존재하는 도메인(searchl.org 실측)은 관측으로 인정 —
    그라운딩이 환각으로 오인해 기각하면 살아있는 클릭사기 TDS 가 정책에서 빠진다."""
    e = ev(hosts=[WS])
    e["external"]["http"] = [{"url": "searchl.org/search?q=x", "dst_ip": "1.2.3.4",
                              "src_ips": ["10.0.0.5"], "method": "GET", "status": 302,
                              "count": 1, "first_ts": 1.0}]
    a = {"iocs": {"c2": [], "delivery": [], "exfil": [], "domains": ["searchl.org"], "hashes": []}}
    ground_iocs(a, ctx_for(a, e))
    assert a["iocs"]["domains"] == ["searchl.org"], a


def test_http_host_bare_ip_not_added_to_observed_domains():
    e = ev(hosts=[WS])
    e["external"]["http"] = [{"url": "1.2.3.4/x", "dst_ip": "1.2.3.4", "src_ips": ["10.0.0.5"],
                              "method": "GET", "status": 200, "count": 1, "first_ts": 1.0}]
    obs = FakeTools(e).observed_iocs()
    assert "1.2.3.4" not in obs["domains"]         # bare-IP 호스트는 도메인 집합에 안 들어감


# ─────────────── C2 technique 게이트 (시그니처 침묵 C2) + THINK 파서 ───────────────
def test_signatureless_c2_target_survives_via_technique():
    """alert 0건(시그니처 침묵)인 C2 를 LLM 이 technique=c2_beacon 으로 적었을 때 —
    표적 제거가 못 지우고 iocs.c2 에 남는다 (q2 실측: 136.243.24.249, 46.108.156.146 회귀)."""
    e = ev(hosts=[WS], ext_ips=["7.7.7.7"])                # alert 없음!
    a = {"victims": [], "attacks": [{"technique": "c2_beacon", "actor": "10.0.0.5",
                                     "target": "7.7.7.7"}],
         "iocs": {"c2": ["7.7.7.7"], "delivery": [], "exfil": [], "domains": [], "hashes": []}}
    run.apply_guards(a, FakeTools(e))
    assert "7.7.7.7" in a["iocs"]["c2"], a
    assert "7.7.7.7" in a.get("_c2_kept_despite_target_label", [])


def test_c2_domain_target_host_survives_via_technique():
    """C2 체크인 attack 의 target_host 도메인(hadevatjulps.com 실증)은 표적 도메인 제거에서 보호."""
    e = ev(hosts=[WS], domains=[("hadevatjulps.com", ["7.7.7.7"])], ext_ips=["7.7.7.7"])
    a = {"victims": [], "attacks": [{"technique": "c2_tordal_checkin", "actor": "10.0.0.5",
                                     "target": "7.7.7.7", "target_host": "hadevatjulps.com"}],
         "iocs": {"c2": [], "delivery": [], "exfil": [], "domains": ["hadevatjulps.com"], "hashes": []}}
    run.apply_guards(a, FakeTools(e))
    assert a["iocs"]["domains"] == ["hadevatjulps.com"], a


def test_non_c2_technique_target_still_removed():
    """technique 가 exploit 류면 target 은 진짜 피격자 — 기존 자폭 방지 그대로."""
    e = ev(hosts=[WS], ext_ips=["8.8.4.4"])
    a = {"victims": [], "attacks": [{"technique": "exploit_sqli", "actor": "10.0.0.5",
                                     "target": "8.8.4.4"}],
         "iocs": {"c2": ["8.8.4.4"], "delivery": [], "exfil": [], "domains": [], "hashes": []}}
    run.apply_guards(a, FakeTools(e))
    assert a["iocs"]["c2"] == [], a


def test_think_parser_levels():
    import config
    p = config._parse_think
    assert p("true", "x") is True and p("false", "x") is False
    assert p("medium", "x") == "medium" and p("HIGH", "x") == "high" and p(None, "low") == "low"
    try:
        p("xhigh2", "x"); assert False, "잘못된 값은 거부"
    except SystemExit:
        pass


# ─────────────── forensic 캐시/replay (개발 루프 가속기) ───────────────
def test_forensic_cache_roundtrip(tmpbase="/tmp/claude-1000/-home-qkekdhd-slm-auto-packet-analyze-v3/f6467c84-eeb5-4912-9291-e32ee6c1bdd7/scratchpad/fc_case"):
    import os, json as _j
    os.makedirs(tmpbase, exist_ok=True)
    if os.path.exists(os.path.join(tmpbase, "forensic_raw.json")):
        os.remove(os.path.join(tmpbase, "forensic_raw.json"))   # 이전 실행 잔재 제거(격리)
    e = ev(hosts=[WS], alerts=[alert("ET MALWARE X", ["10.0.0.5"], ["9.9.9.9"], "threat")])
    _j.dump(e, open(os.path.join(tmpbase, "evidence.json"), "w"))
    t = Tools.__new__(Tools); t.base = tmpbase; t.evidence = e
    # 캐시 없음 → replay 는 에러
    try:
        run.forensic(t, "replay"); assert False, "캐시 없는 replay 는 LLMError"
    except run.LLMError:
        pass
    # 캐시 수동 주입(=fresh 가 저장했다 치고) 후 replay 가 그 content 를 파싱
    payload = {"iocs": {"c2": ["9.9.9.9"]}, "victims": []}
    msgs = run._forensic_messages(t)
    _j.dump({"prompt_sha": run._prompt_sha(msgs), "model": run.MODEL, "think": run.THINK,
             "content": _j.dumps(payload)}, open(os.path.join(tmpbase, "forensic_raw.json"), "w"))
    got = run.forensic(t, "replay")
    assert got == payload, got
    # auto 모드 + sha 일치 → LLM 없이 캐시 재생 (여기서 ollama 를 import 하면 실패해야 정상)
    got2 = run.forensic(t, "auto")
    assert got2 == payload, got2


if __name__ == "__main__":
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = []
    for name, fn in tests:
        try:
            fn()
            print(f"  ok   {name}")
        except AssertionError as ex:
            failed.append(name)
            print(f"  FAIL {name}: {ex}")
        except Exception as ex:                      # 예외도 실패 — 가드가 크래시하면 리포트가 통째로 죽는다
            failed.append(name)
            print(f"  ERR  {name}: {type(ex).__name__}: {ex}")
    print(f"\n{len(tests) - len(failed)}/{len(tests)} passed" + (f"  — FAILED: {failed}" if failed else ""))
    sys.exit(1 if failed else 0)
