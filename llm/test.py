import json
from ollama import chat, ChatResponse

from tools import TOOLS, AVAILABLE   # llm/ 안에서 실행 기준

MODEL = "gemma4:26b"


def test_hello():
    response: ChatResponse = chat(model=MODEL, messages=[
        {"role": "user", "content": "안녕하세요? 당신은 누구입니까?"}
    ])
    print(response.message.content)


def test_tool_call():
    """일단 test_tool 이 잘 불리는지 확인용."""
    messages = [{
        "role": "user",
        "content": "테스트용 툴 돌려줘. arg1엔 나한테 하고 싶은 말을 넣어.",
    }]
    # 함수 객체를 그대로 넘김 → ollama 가 타입힌트+docstring 으로 스키마 자동 생성
    response: ChatResponse = chat(model=MODEL, messages=messages, tools=TOOLS)

    print("tool_calls:", response.message.tool_calls)

    for tc in (response.message.tool_calls or []):
        name = tc.function.name
        args = tc.function.arguments            # dict
        fn = AVAILABLE.get(name)                # 이름 → 실제 함수 디스패치
        result = fn(**args) if fn else {"error": f"unknown tool: {name}"}
        print("호출:", name, args)
        print("결과:", result)


def main():
    test_hello()
    test_tool_call()


if __name__ == "__main__":
    main()
