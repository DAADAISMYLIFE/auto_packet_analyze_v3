# CLAUDE.md

이 파일은 이 저장소에서 작업하는 Claude Code(및 AI 어시스턴트)를 위한 안내다.

## 협업 규칙 (중요)
- **사용자가 명시적으로 "코드를 짜달라 / 수정해라 / 삭제해라"라고 말하기 전까지, 코드 파일을 생성·수정·삭제하지 않는다.** 그 전에는 **코드를 채팅으로 보여주기만** 한다. 판단과 결정은 사용자가 한다.
- 문서(README, CLAUDE.md 등)와 비(非)코드 작업(git commit, 스크립트 실행)은 위 규칙과 별개로 요청 시 수행한다.
- 커밋은 어시스턴트가 해도 되지만 **push는 사용자가 직접** 한다.

## 프로젝트 목적
pcap을 넣으면 자동으로 네트워크 포렌식 분석을 수행하고, 사람은 **마지막에 보고서를 읽고 차단 정책 적용 여부(o/x)만 선택**한다. "인간 개입의 최소화"가 핵심 목표다.

## 파이프라인 (목표)
1. 사용자가 pcap 업로드
2. `scripts/extract_log.sh <pcap>` → Suricata + Zeek 로그 추출 (1차 검증)
3. 정규화 및 압축 → "evidence 번들"
4. LLM 분석: 피해자 정보(ip/mac/hostname/username), 공격자 정보, 공격 행위 판단, 타임라인/시나리오, 차단 정책(패턴) 생성
5. LLM 보고서 생성 + 질문("~해서 ~패턴을 생성했습니다. 적용하시겠습니까?")
6. 사용자의 선택 (판단 근거는 LLM이 모두 제공)

## 구조
```
setup.sh                 # suricata/zeek/ollama 설치 + 모델 pull + test.py 실행
scripts/
  run_suricata.sh        # pcap → suricata eve.json (OUT_DIR 로 출력경로 지정 가능)
  run_zeek.sh            # pcap → zeek NDJSON 로그 (native 또는 docker)
  extract_log.sh <pcap>  # 위 둘을 한번에 → output/<pcap이름>/{suricata,zeek}
llm/
  tools.py               # tool 함수 + 자동 스키마 등록소(TOOLS/AVAILABLE)
  test.py                # tool-calling 동작 확인용
pcaps/                   # 테스트 pcap (git ignore)
output/                  # 분석 산출물 (git ignore)
venv/                    # 파이썬 venv (git ignore, 이식 불가 — 각 환경서 새로 생성)
```

## LLM / tools
- Ollama 로컬 모델 사용 (현재 `gemma4:26b`).
- 새 tool 추가 = `llm/tools.py`에 **타입힌트 + docstring** 갖춘 함수 정의 후 **`TOOLS` 리스트에 등록**. 스키마는 ollama가 자동 생성하고 `AVAILABLE`(이름→함수)은 자동 파생된다.
- llm 코드는 `llm/` 디렉터리 안에서 실행한다(`from tools import ...` 기준).

## 실행
```bash
./setup.sh                                  # 최초 환경 구성 (모델명은 MODEL 환경변수로 변경 가능)
./scripts/extract_log.sh pcaps/<파일>.pcap  # 로그 추출
cd llm && python3 test.py                    # tool-calling 확인
```
