import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_PATH = os.path.join(ROOT, "output")   # output/<pcap이름>/{suricata,zeek}/...


# =============================================================================
# tool 함수들
#   - 타입힌트(arg: str) 와 docstring 을 잘 써야 자동 스키마가 정확히 나옴.
#     (모델은 이 description 을 보고 "언제/어떻게 부를지" 판단함)
#   - 새 tool 추가 = 아래에 함수 정의 + 맨 밑 TOOLS 리스트에 이름만 등록.
# =============================================================================

def test_tool(arg1: str) -> dict:
    """테스트용 함수. 입력받은 값을 그대로 되돌려준다.

    Args:
        arg1: 아무 문자열이나. 테스트용 매개변수.
    """
    return {"결과": True, "인수1": arg1}


def get_log(filename: str, limit: int = 100) -> list:
    """output/ 아래의 NDJSON 로그(.log / eve.json)를 읽어 레코드 리스트로 반환한다.

    Args:
        filename: output 기준 상대경로. 예) 'test-http/suricata/eve.json',
                  'test-http/zeek/conn.log'
        limit: 최대 줄 수. 큰 파일이 컨텍스트를 터뜨리지 않게 잘라준다.
    """
    # ROOT/output 에 filename 합치기
    path = os.path.realpath(os.path.join(LOGS_PATH, filename))

    # 경로 탈출(../) 방지 — output 밖이면 거부
    if not path.startswith(os.path.realpath(LOGS_PATH) + os.sep):
        return {"error": f"허용되지 않은 경로: {filename}"}
    if not os.path.isfile(path):
        return {"error": f"파일 없음: {filename}"}

    # zeek/suricata 로그는 NDJSON (한 줄에 JSON 1개) → 줄 단위로 파싱
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue   # 깨진 줄은 건너뜀
            if len(records) >= limit:
                break
    return records


# =============================================================================
# 등록소 — 새 tool 은 여기에 함수 이름만 추가하면 됨.
#   TOOLS     : chat(tools=TOOLS) 로 넘김 → ollama 가 함수에서 스키마 자동 생성
#   AVAILABLE : 모델이 부른 이름 → 실제 함수 (실행용 디스패치). 자동 파생.
# =============================================================================
TOOLS = [
    test_tool,
    get_log,
]
AVAILABLE = {fn.__name__: fn for fn in TOOLS}
