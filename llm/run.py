import sys, json

from tools import Tools
from ollama import chat

MODEL = "gemma4:26b"
MAX_TURNS = 5          # tool 루프 무한방지

def chatting(tools):
    # 채팅 기본 구조
    messages = [
        {"role": "system",
         "content": "You are a network forensics analyst. Use the provided tools to "
                    "gather facts. Never invent IPs, hostnames, or usernames."},
        {"role": "user",
         "content": "Identify the victim / internal hosts using the tools."},
    ]

    for _ in range(MAX_TURNS):
        res = chat(model=MODEL, messages=messages, tools=tools.TOOLS)

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