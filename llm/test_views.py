#!/usr/bin/env python3
"""LLM 뷰(단계적 http 강등) + 컨텍스트 예산 테스트 — LLM/GPU 없이 1초.

anti-overfit 계약을 여기서 잠근다:
  - 예산 안이면 level 0 = 오늘과 동일 (뷰가 raw 리스트 그대로)
  - '처음 보는' 인바운드 페이로드(어떤 패턴 목록에도 없음)가 모든 단계에서 살아남는다
  - 신호 행(비콘 목적지 등)은 level 3 까지 전량, 신호 없는 행만 줄어든다
  - 접은 건 건수를 보존하고 _view 로 알린다
  - 예산을 최대 강등 후에도 넘기면 ollama 호출 '전'에 실패한다

실행:  cd llm && python3 test_views.py
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_guards import FakeTools, ev
import run
from run import estimate_tokens, _tier1, LLMError, _is_threat_alert
from tools import is_threat_alert


def http_row(url, dst, src="10.0.0.5", **kw):
    r = {"url": url, "method": "GET", "dst_ip": dst, "status": 200, "user_agent": "UA",
         "req_body": None, "resp_body": None, "req_headers": None,
         "src_ips": [src], "count": 1, "first_ts": 100.0}
    r.update(kw)
    return r


def with_http(rows, **kw):
    e = ev(hosts=[("10.0.0.5", "workstation", None), ("10.0.0.9", "server", None)], **kw)
    e["external"]["http"] = rows
    return e


NOVEL = "ZQX-never-seen-payload-77 {{unknown-technique}}"   # WEB_ATTACK_PAT 어디에도 없음


def test_level0_is_raw_list():
    t = FakeTools(with_http([http_row("a.com/x", "1.1.1.1")]))
    assert t.http_view(0) == t.get_http() and isinstance(t.http_view(0), list)


def test_novel_inbound_payload_survives_every_level():
    rows = [http_row("10.0.0.9/login", "10.0.0.9", src="203.0.113.7",
                     req_headers=NOVEL + " | ACCEPT: */*", req_body=NOVEL)]
    rows += [http_row(f"cdn{i}.com/{i}", "1.1.1.1", resp_body="<html>" * 50) for i in range(20)]
    t = FakeTools(with_http(rows))
    for level in range(1, t.HTTP_VIEW_LEVELS):
        blob = json.dumps(t.http_view(level), ensure_ascii=False)
        assert NOVEL in blob, f"level {level}: 처음 보는 인바운드 페이로드가 사라짐"


def test_signal_rows_full_until_level3_others_shrink():
    big = "R" * 300
    beacon = http_row("evil.net/beacon", "9.9.9.9", resp_body=big, req_headers=big)
    noise = http_row("cdn.com/js", "1.1.1.1", resp_body=big, req_headers=big)
    e = with_http([beacon, noise])
    e["anomalies"] = {"beacons": [{"dst": "9.9.9.9"}]}          # 9.9.9.9 = 이상행동 목적지 → 신호 행
    t = FakeTools(e)
    for level in (1, 2, 3):
        v = t.http_view(level)
        assert v["signal_rows"] == [beacon], f"level {level}: 신호 행이 전량이 아님"
    v1 = t.http_view(1)
    o = v1["other_rows"][0]
    assert len(o["resp_body"]) <= 81 and o["resp_body"].endswith("…")   # 지문 + 표시
    assert v1["_view"]["total_rows"] == 2 and v1["_view"]["signal_rows"] == 1


def test_fold_preserves_counts_and_sample():
    rows = [http_row(f"ads.com/click/{'abcdefgh'[i:]}{i}92{i}", "1.1.1.1", count=3) for i in range(5)]
    t = FakeTools(with_http(rows))
    v = t.http_view(2)
    assert v["signal_rows"] == []
    assert len(v["other_groups"]) == 1, v["other_groups"]
    g = v["other_groups"][0]
    assert g["requests"] == 15 and g["rows_folded"] == 5 and g["sample_url"].startswith("ads.com/")
    assert "groups" in v["_view"]["other_shown_as"]


def test_level3_and_4_summaries_keep_totals():
    rows = [http_row(f"x{i}.com/p", "1.1.1.1", count=2) for i in range(4)]
    rows += [http_row("10.0.0.9/admin", "10.0.0.9", src="203.0.113.7", req_body=NOVEL)]
    t = FakeTools(with_http(rows))
    v3 = t.http_view(3)
    assert v3["other_summary"][0]["requests"] == 8 and v3["other_summary"][0]["rows"] == 4
    v4 = t.http_view(4)
    assert NOVEL in json.dumps(v4["signal_groups"], ensure_ascii=False)
    assert v4["_view"]["signal_rows"] == 1 and v4["_view"]["other_rows"] == 4


def test_cap_representation_and_inbound_both_survive():
    """계약 쌍(overfit 감시관): 캡 포화 인바운드 공격 + 침묵 호스트 다수 → 둘 다 생존.
    예약석이 tier 최소 할당을 침범하지 않고, 침묵 호스트도 투명인간이 안 된다."""
    import sys as _s, os as _o
    _s.path.insert(0, _o.path.join(_o.path.dirname(_o.path.abspath(__file__)), "..", "scripts"))
    from build_evidence import signal_priority_cap
    inbound = [{"url": f"10.0.0.9/atk{i}", "first_ts": float(i), "count": 1, "_in": True}
               for i in range(150)]
    noise = [{"url": f"n{i}.example/x", "first_ts": 500.0 + i, "count": 1, "_in": False}
             for i in range(150)]                    # 노이즈가 시간상 먼저 — 시간순 운빨 차단
    silent = [{"url": f"quiethost.example/u{i}", "first_ts": 5000.0 + i, "count": 40, "_in": False}
              for i in range(3)]
    trunc = {}
    got = signal_priority_cap(inbound + silent + noise, 100, trunc, "t",
                              priority=lambda x: 100 if x["_in"] else 0,
                              host_of=lambda x: str(x.get("url")).split("/", 1)[0])
    urls = [g["url"] for g in got]
    assert sum(1 for u in urls if u.startswith("10.0.0.9/")) >= 40      # tier 최소 할당(예약 공제 후) 보장
    assert any(u.startswith("quiethost.example/") for u in urls), trunc  # 침묵 호스트 대표 생존
    assert trunc.get("t_repr_added", 0) >= 1


def test_summary_keeps_host_identity():
    rows = [http_row("wajam.example/webenhancer/update?v=1", "1.2.3.4", count=40)]
    t = FakeTools(with_http(rows))
    summ = t._summarize_by_dst(rows)
    assert summ[0]["host"] == "wajam.example" and "webenhancer" in summ[0]["sample_url"]


def test_estimator_is_digit_aware():
    assert estimate_tokens("192.168.0.1") >= 11          # 8 자릿수 + 점 3 (3.3자/토큰이면 3)
    assert estimate_tokens("hello world") < 6


def test_tier1_escalates_then_refuses_before_calling():
    rows = [http_row(f"cdn{i}.com/{i}", "1.1.1.1", resp_body="B" * 250, req_headers="H" * 250) for i in range(60)]
    t = FakeTools(with_http(rows))
    saved = run.NUM_CTX
    try:
        run.NUM_CTX = 10_000                                 # forensic 예산 6,000 → level 0 은 못 들어감
        text = _tier1(t, "forensic")
        assert estimate_tokens(text) <= 6_000 and '"_view"' in text   # 강등해서 들어감 + 강등 사실 명시
        run.NUM_CTX = 300                                    # 아무리 줄여도 안 들어감
        try:
            _tier1(t, "forensic")
            assert False, "LLMError 가 나야 함 (호출 전 거부)"
        except LLMError as ex:
            assert "호출 안 함" in str(ex)
    finally:
        run.NUM_CTX = saved


def test_small_case_never_degraded():
    rows = [http_row(f"s{i}.com/a", "1.1.1.1", resp_body="x" * 200) for i in range(5)]
    t = FakeTools(with_http(rows))
    text = _tier1(t, "forensic")
    assert '"_view"' not in text                           # 예산 안 → level 0 → 뷰 래퍼 없음(오늘과 동일)


def test_threat_alert_single_source():
    assert _is_threat_alert is is_threat_alert
    assert is_threat_alert({"threat_class": "rat"}) and not is_threat_alert({"threat_class": "benign", "signature": "ET MALWARE x"})
    assert is_threat_alert({"signature": "ET MALWARE x"})   # 구 evidence 폴백


def test_noalert_ablation_removes_only_alerts():
    """시그니처 제거 ablation 계약: 같은 로그에서 알럿만 0, 나머지(호스트·외부 IP)는 동일,
    _ablation 표식은 밑줄 키(LLM 번들 미노출)."""
    import tempfile, os as _o, sys as _s
    _s.path.insert(0, _o.path.join(_o.path.dirname(_o.path.abspath(__file__)), "..", "scripts"))
    from build_evidence import build_evidence, ABLATION_SUFFIX
    import run as _run
    with tempfile.TemporaryDirectory() as root:
        z = _o.path.join(root, "output", "x", "zeek"); s_ = _o.path.join(root, "output", "x", "suricata")
        _o.makedirs(z); _o.makedirs(s_)
        conn = {"ts": 1700000000.0, "uid": "C1", "id.orig_h": "10.0.0.5", "id.orig_p": 50000,
                "id.resp_h": "9.9.9.10", "id.resp_p": 80, "proto": "tcp", "conn_state": "SF",
                "local_orig": True, "local_resp": False, "orig_bytes": 100, "resp_bytes": 200,
                "duration": 1.0, "community_id": "1:abc"}
        open(f"{z}/conn.log", "w").write(json.dumps(conn) + "\n")
        alert = {"timestamp": "2023-11-14T22:13:20.000000+0000", "event_type": "alert",
                 "community_id": "1:abc", "src_ip": "10.0.0.5", "dest_ip": "9.9.9.10",
                 "alert": {"signature": "ET MALWARE Example CnC Checkin",
                           "category": "A Network Trojan was detected", "severity": 1}}
        open(f"{s_}/eve.json", "w").write(json.dumps(alert) + "\n")
        full = build_evidence("x", root)
        abl = build_evidence("x", root, noalert=True)
    assert len(full["alerts"]) == 1 and abl["alerts"] == [], (full["alerts"], abl["alerts"])
    assert [h["ip"] for h in full["hosts"]] == [h["ip"] for h in abl["hosts"]]
    assert {e["ip"] for e in full["external"]["ips"]} == {e["ip"] for e in abl["external"]["ips"]}
    assert abl.get("_ablation") == "noalert" and "_ablation" not in full
    assert ABLATION_SUFFIX == "-noalert"
    # LLM 번들에 표식이 새지 않는다 (밑줄 키는 _bundle 에 없음)
    from test_guards import FakeTools
    t = FakeTools(abl)
    assert "noalert" not in _run._bundle(t, t.http_view(0))


def test_score_ablation_label_and_truth_key():
    """채점기: -noalert 행은 원본 truth 로 채점하되 표에서는 접미사로 구분된다."""
    import os as _o, sys as _s
    _s.path.insert(0, _o.path.join(_o.path.dirname(_o.path.abspath(__file__)), "..", "scripts"))
    from score import case_of, label_of
    assert case_of("reports/q2-noalert.json") == "q2" and label_of("reports/q2-noalert.json") == "q2-noalert"
    assert case_of("reports/2024-11-26-traffic-analysis-exercise-noalert.json") == "20241126"
    assert label_of("reports/2024-11-26-traffic-analysis-exercise-noalert.json") == "20241126-noalert"
    assert case_of("reports/q2.json") == "q2" and label_of("reports/q2.json") == "q2"


if __name__ == "__main__":
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = []
    for name, fn in tests:
        try:
            fn(); print(f"  ok   {name}")
        except AssertionError as ex:
            failed.append(name); print(f"  FAIL {name}: {ex}")
        except Exception as ex:
            failed.append(name); print(f"  ERR  {name}: {type(ex).__name__}: {ex}")
    print(f"\n{len(tests) - len(failed)}/{len(tests)} passed" + (f"  — FAILED: {failed}" if failed else ""))
    sys.exit(1 if failed else 0)
