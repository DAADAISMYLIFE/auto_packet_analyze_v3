# auto_packet_analyze_v3

PCAP을 Suricata/Zeek로 처리하고, **결정론적 사건 사실(case facts) → 제한된 LLM 판단 →
Suricata 정책 → 한글 보고서**를 생성하는 로컬 네트워크 포렌식 파이프라인이다.
사람은 마지막에 근거와 정책을 확인하고 적용 여부만 선택한다.

## 핵심 원칙

### 코드는 사실과 안전을 소유한다

패킷에 이미 있는 IP·도메인·해시·호스트·방향·시간을 LLM에게 다시 받아 적게 하지 않는다.
`llm/case_facts.py`가 evidence를 다음과 같이 결정론적으로 변환한다.

- 내부/외부 scope와 통신 방향
- 위협 경보와 HTTP 공격 패턴
- 감염 후 행동이 있는 호스트와 단순 피격 호스트의 구분
- 외부 공격자와 C2/delivery/exfil의 의미 분리
- 관측값별 confidence, evidence ref, 정책 적격성
- 보수적 verdict, patient zero, 타임라인

결과는 `output/<case>/case_facts.json`에 저장된다. LLM이 없어도 기존 소비 계약과 호환되는
`reports/<case>.json`이 생성된다.

### LLM은 제한된 판단만 한다

LLM 입력은 raw evidence 전체가 아니라 기본 48,000자 예산의 작은 case-facts packet이다.
모델은 코드가 발급한 `obs:*`, `attack:*` ID 안에서만 다음을 보강한다.

- 시그니처가 뒷받침하는 멀웨어 family 명칭
- 고신뢰 후보의 의미 bucket
- 코드가 `unknown`으로 남긴 공격 disposition
- 한글 요약과 커버리지 한계

후보 밖 값, 존재하지 않는 evidence ref, host/attack ID는 검증에서 거부한다. 실패한 경우 전체
분석을 무한 반복하지 않고 오류를 첨부해 기본 1회만 복구 요청한다. 복구도 실패하면 결정론적
보고서를 그대로 사용한다. 패킷의 URI/body/header/hostname 문자열은 명시적으로 비신뢰 데이터로
취급하며 지시문으로 해석하지 않는다.

### 탐지와 차단은 다르다

모든 관측 후보는 `analysis.observables`에 남지만, 다음 조건을 만족한 값만 `analysis.iocs` 또는
`analysis.attackers`로 승격되어 정책 입력이 된다.

- 코드가 실제 관측값과 provenance를 확인
- confidence가 `high`
- 코드가 `policy_eligible=true`로 판정

LLM은 `policy_eligible`을 올릴 수 없다. 해시는 보고서 IOC로 쓸 수 있지만 Suricata 정책 생성기는
해시 차단을 하지 않는다. 외부 공격자는 `attackers`에 별도 보관하되 정책에서는 차단한다.

## 파이프라인

```text
pcap
  │ scripts/extract_log.sh
  ▼
Suricata eve.json + Zeek NDJSON
  │ scripts/build_evidence.py
  ▼
evidence.json
  │ llm/case_facts.py (결정론적)
  ▼
case_facts.json ───────────────┐
  │ llm/run.py                 │ LLM 실패 시에도 진행
  ▼                            │
reports/<case>.json ◀──────────┘
  │ scripts/make_policy.py
  ▼
reports/<case>.rules
  │ llm/render_report.py
  ▼
reports/<case>.md → [ o / x ]
```

## Evidence 예산

`build_evidence.py`는 단순 시간순 선착순으로 cap을 채우지 않는다. 다음 자료를 먼저 보존하고,
선택된 결과는 다시 시간순으로 정렬한다.

- alert-linked IP/도메인
- 공격 payload가 있는 HTTP 요청
- 의심 TLD
- 위협 카테고리 alert

따라서 긴 캡처 후반의 공격이 초반 정상 HTTP/DNS 트래픽 때문에 잘리는 문제를 방지한다.
잘린 개수는 `_truncation`에 기록되고 case facts와 LLM packet에도 전달된다. alert도 300개로 제한하되
숫자 severity보다 MALWARE/EXPLOIT 등의 위협 카테고리를 먼저 보존한다.

## 실행

```bash
./setup.sh
./scripts/extract_log.sh pcaps/<file>.pcap
python3 scripts/build_evidence.py <case>

# 결정론적 분석만: Ollama 없이도 동작
python3 llm/run.py <case> --no-llm

# 결정론적 분석 + 제한된 LLM judgment
python3 llm/run.py <case>

python3 scripts/make_policy.py <case> --validate
python3 llm/render_report.py <case>
```

주요 설정은 `.env`에서 읽는다.

```dotenv
MODEL=qwen3.8:27b-mtp-q4_K_M
NUM_CTX=65536
TEMPERATURE=0.3
SEED=42
CONTEXT_MAX_CHARS=48000
REPAIR_ATTEMPTS=1
```

`CONTEXT_MAX_CHARS`와 `REPAIR_ATTEMPTS`는 `.env`에 없어도 위 기본값으로 동작한다.

## 평가 루프

단일 보고서 또는 두 실험 디렉터리를 비교한다.

```bash
python3 scripts/score.py reports
python3 scripts/score.py --compare experiments/A/model/seed-42 experiments/B/model/seed-42
python3 scripts/score.py reports --json
```

채점기는 verdict와 grounding 외에 다음을 측정한다.

- victim precision/recall/F1
- IOC IP, domain, hash precision/recall/F1
- c2/delivery/exfil 의미 bucket
- 예상 밖 compromised 호스트와 인프라 오인
- 명시된 정상 IP/해시 오탐
- patient zero와 선택적 technique coverage

여러 모델과 seed를 반복 실행하려면:

```bash
python3 scripts/evaluate.py \
  --cases 20210616 20211022 whatthef \
  --models qwen3.8:27b-mtp-q4_K_M gemma3:27b \
  --repeats 3
```

각 실행의 report, stdout/stderr, 실행시간, LLM token/duration metadata와 점수는
`experiments/<UTC timestamp>/` 아래에 보존된다. `reports/<case>.json` 덮어쓰기와 무관하게 이전
실험을 비교할 수 있다.

## 테스트

```bash
python3 -m compileall -q llm scripts tests
python3 -m unittest discover -s tests -v
bash -n setup.sh scripts/*.sh
```

오프라인 회귀 테스트는 정상 sev1 INFO 경보, C2, 인바운드 공격자/C2 분리, 패킷 프롬프트 인젝션,
후반 evidence 보존, 도메인 경계, 공용접미사 과차단, 존재하지 않는 LLM ID를 검사한다.

## 구조

```text
llm/
  case_facts.py       # evidence → 결정론적 사건 사실과 기존 report 골격
  run.py              # 제한된 LLM judgment, 검증/1회 복구, 실행 artifact
  tools.py            # evidence 로더와 provenance helper
  render_report.py    # 코드 표 + 최소 안전 컨텍스트의 한글 서술
scripts/
  build_evidence.py   # 로그 조인, 중요도 기반 evidence 선택
  baseline.py         # 정상 대비 편차
  domain_utils.py     # 라벨 경계 및 흔한 다중라벨 suffix 처리
  make_policy.py      # 결정론적 Suricata 정책
  score.py            # precision/recall/F1 평가
  evaluate.py         # 모델/seed 반복 평가 루프
answers/truth/        # 사람 검수 ground truth
```

## 남아 있는 천장

- TLS/DoH 내부 payload와 캡처 이전·이후 행위는 PCAP만으로 확정할 수 없다.
- 도메인 유틸리티는 외부 의존성을 피하려 흔한 다중라벨 suffix만 포함한다. 전 세계 TLD를 다룰 때는
  고정 버전 Public Suffix List가 필요하다.
- `confirmed`는 감염 후 행동/성공 증거를 요구하도록 보수적으로 계산한다. 미관측 행위를 추측해
  recall을 올리지 않는다.
- 최종 운영 성능은 실제 `output/` 케이스와 정상/의심/확정이 균형 잡힌 holdout에서 반복 측정해야 한다.
- 공유 CDN IP 차단 방지는 현재 코드에 내장된 대역 목록 범위에 한정된다.
