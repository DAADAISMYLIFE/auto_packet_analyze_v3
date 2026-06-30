from ollama import chat
from ollama import ChatResponse

def main():
    response: ChatResponse = chat(model='gemma4:26b', messages=[{
        'role': 'user',
        'content' : '안녕하세요? 당신은 누구입니까?'
    },
    ])

    print(response.message.content)

if __name__ == "__main__":
    main()