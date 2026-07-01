from ollama import chat
from ollama import ChatResponse

from tools import TOOL_SCHEMAS
from tools import test_tool


def test_hello():
    response: ChatResponse = chat(model='gemma4:26b', messages=[{
        'role': 'user',
        'content' : '안녕하세요? 당신은 누구입니까?'
    },
    ])
    print(response.message.content)

def test_tool_call():
    response: ChatResponse = chat(model='gemma4:26b', tools=TOOL_SCHEMAS,
    messages=[{
        'role': 'user',
        'content' : '테스트용 툴 돌리면 뭐가 나와? arg1엔 너가 나한테 하고싶은말'
        },
    ])

    print("tool_calls:", response.message.tool_calls)
    
    for tc in (response.message.tool_calls or []):
        print("호출:", tc.function.name, tc.function.arguments)
        print("결과:", test_tool(**tc.function.arguments))

def main():
    test_hello()
    test_tool_call()

 

if __name__ == "__main__":
    main()