import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_PATH = os.path.join(ROOT, "output")   # output/<pcap이름>/{suricata,zeek}/...

TOOL_SCHEMAS = [{
    # test_tool 호출용
    "type": "function",
      "function": {
        "name": "test_tool",
        "description": "테스트용 함수를 호출합니다.",
        "parameters": {
          "type": "object",
          "required": ["arg1"],
          "properties": {
            "arg1": {"type": "string", "description": "테스트용 매개변수 입니다."}
          }
        }
      }
    },
    # 다른거
]

def test_tool(arg1):
    return {"결과" : True, "인수1": arg1}

def get_log(filename, limit=100):
    """output/ 아래의 NDJSON 로그(.log / eve.json)를 읽어 레코드 리스트를 반환.

    filename 예: 'test-http/suricata/eve.json'
                 'test-http/zeek/conn.log'
    limit: 너무 큰 파일이 컨텍스트를 터뜨리지 않게 최대 N줄만.
    """
    # ROOT/output 에 filename 합치기 (placeholder 였던 부분)
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
    print(records)
    return records


