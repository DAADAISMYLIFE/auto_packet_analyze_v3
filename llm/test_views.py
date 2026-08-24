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
