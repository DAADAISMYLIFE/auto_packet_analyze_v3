# CLAUDE.md

이 파일은 이 저장소에서 작업하는 Claude Code(및 AI 어시스턴트)를 위한 안내다.

## 협업 규칙 (중요)
- **사용자가 명시적으로 "코드를 짜달라 / 수정해라 / 삭제해라"라고 말하기 전까지, 코드 파일을 생성·수정·삭제하지 않는다.** 그 전에는 **코드를 채팅으로 보여주기만** 한다. 판단과 결정은 사용자가 한다.
- 문서(README, docs/, CLAUDE.md 등)와 비(非)코드 작업(git commit, 스크립트 실행, 채점)은 위 규칙과 별개로 요청 시 수행한다.
- 커밋은 어시스턴트가 해도 되지만 **push는 사용자가 직접** 한다.
- 큰 변경·성능 주장 전에는 **레드팀 페르소나(서브에이전트)** 심사를 거친다. 오버핏(특정 케이스에 맞춘 규칙·임계값) 감시가 그 역할이다.

## 프로젝트 목적
pcap을 넣으면 자동으로 네트워크 포렌식 분석을 수행하고, 사람은 **마지막에 보고서를 읽고 차단 정책 적용 여부(o/x)만 선택**한다.
"인간 개입의 최소화"가 목표이되, 실측이 정한 역할 분담을 따른다: **코드가 심판(팩트·행동 판단·승격·룰), LLM은 판독기 + 서술**.

## 지켜야 할 원칙 (실측으로 얻은 것 — docs/HISTORY.md, docs/MEASUREMENTS.md)
- **실측 없이 주장하지 않는다.** 성능 표는 항상 [코드-only 바닥 / +LLM] 두 행. 숫자에는 커밋·모델·설정을 붙인다.
- **규칙·임계값에 케이스 이름을 넣지 않는다.** 승격기·가드는 반례 테스트 쌍(승격 1 + 비승격 N)으로 잠근다.
- **ollama 공식 표준 태그만 쓴다.** 커뮤니티 양자화·비표준 태그 금지(2026-09-02 P100 사고).
- **진단은 파이프라인과 동일 옵션(config.OPTS)으로.** 옵션이 다르면 스필을 못 잡는다(num_batch 사고).
- **컨텍스트는 키우는 게 아니라 고르는 것.** 예산 초과는 뷰 강등으로, 그래도 넘치면 호출 전 실패.
- `.env` 인라인 주석은 별도 줄에만(파서가 깨진다).

## 구조
```
setup.sh                 조용·멱등 설치 + 캐시 데이터셋 복원 (MODEL 환경변수)
.env                     설정 단일 소스 (MODEL/NUM_CTX/THINK/샘플링/NUM_PREDICT)
scripts/
  extract_log.sh <pcap>  Suricata + Zeek → output/<name>/{suricata,zeek}
  build_evidence.py      로그 → output/<name>/evidence.json (결정론). --noalert = 알럿만 0 (ablation)
  baseline.py            정상/편차 엔진, threat_class(), DNS 검색 접미사
  make_policy.py         reports/<name>.json → .rules (순수 코드)
  score.py               truth 대비 recall/precision, --compare A B
llm/
  config.py              .env 로더 + REPORT/VERDICT 스키마 + 프롬프트 로드
  tools.py               evidence 읽기 API (tool-calling 아님 — 이름은 유산)
  run.py                 code_triage → forensic(캐시 auto/--fresh/--replay) → PASSES 가드 → 승급 → _llm_delta / --floor
  render_report.py       한국어 MD 보고서 (코드 표 + LLM 서술 1콜)
  prompts/*.md           forensic(6단계 절차) / triage(조용한 캡처 판별)
  test_guards.py, test_views.py   GPU 없이 1초 (노트북이 파이프라인 전에 게이트로 실행)
kaggle/run_pipeline.ipynb   7셀, 항상 Run All (Phase A 바닥 → Phase B LLM, ABLATION 스위치)
answers/truth/           채점용 정답 원자 (답안 원문·PDF는 gitignore)
docs/                    ARCHITECTURE / HISTORY / MEASUREMENTS / REVIEW-2026-09 / results/
output/, reports/        gitignore (산출물은 docs/results 에 사본 보존)
```

## LLM
- Ollama 로컬 모델, 현재 `qwen3.8:27b`(공식 태그), THINK=medium, NUM_CTX=131072, Kaggle T4×2.
- 분석 경로는 **tool-calling을 쓰지 않는다** — tier1 evidence를 메시지에 주입 + `format=` JSON 스키마 강제 단일 chat.
  (ollama에서 format 과 tools 는 공존 불가.)
- 모델 교체는 `.env`의 MODEL 한 줄. thinking 미지원 모델은 run.py의 think 파라미터에 400 이 나므로 코드 수정이 필요하다.
- llm 코드는 `llm/` 디렉터리 안에서 실행한다(`from tools import ...` 기준).

## 실행
```bash
./setup.sh
./scripts/extract_log.sh pcaps/<파일>.pcap
python3 scripts/build_evidence.py <name> [--noalert]
cd llm && python3 test_guards.py && python3 test_views.py
cd llm && python3 run.py <name> --floor        # 코드-only 바닥
cd llm && python3 run.py <name>                # LLM (evidence 동일하면 캐시 재생)
python3 scripts/make_policy.py <name> --validate
cd llm && python3 render_report.py <name>
python3 scripts/score.py --compare reports/floor reports
```

## 현재 상태 (2026-09-10)
1차 마무리. 열린 티켓은 docs/REVIEW-2026-09.md의 TOP 10 — 우선순위 결정은 사용자 몫.
