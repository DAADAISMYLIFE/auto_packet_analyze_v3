# auto_packet_analyze_v3

**pcap 하나 → Suricata/Zeek → 결정론 evidence → 로컬 LLM → Suricata 차단 룰 + 한국어 보고서. 사람은 마지막에 [ o / x ]만.**

pcap을 Suricata/Zeek로 풀어 결정론 evidence로 정규화하고, **코드가 팩트**(그라운딩·인프라 보호·IOC 승격)를 소유하고
**로컬 LLM(ollama, qwen3.8:27b)은 판독과 서술**만 맡도록 층을 나눈 파이프라인이다. LLM 0회의 **코드-only 바닥(floor)** 을
상설 기준선으로 두어 LLM의 기여를 델타로 기록한다. 외부 위협인텔은 쓰지 않는다 — pcap + 시그니처 + 행동만으로 얼마나
가는지가 평가 기준이다.

교육용 pcap 6개에서 전 단계를 완주했다. 다만 **무혐의 케이스 부재 · 개발 케이스(q2) 의존 · truth가 evidence에서 유래**라는
측정 한계가 있고, 아래 수치는 그 한계 안에서만 유효하다 ([docs/MEASUREMENTS.md](docs/MEASUREMENTS.md)).

---

## 무엇을 하나

```
pcap
 │  scripts/extract_log.sh          Suricata(ET Open) + Zeek → 로그
 ▼
 │  scripts/build_evidence.py       결정론 정규화·캡·편차 랭크 → evidence.json      (판단 없음)
 ▼                                  --noalert: 알럿만 0으로 만든 ablation 행
 │  llm/run.py --floor              코드-only 바닥: 승격기 + 가드, LLM 0회 (2초)     ← 기준선
 │  llm/run.py                      code_triage → forensic(LLM 1콜, JSON 강제, 캐시) → 가드 → 승급 → LLM델타
 ▼
 │  scripts/make_policy.py          IOC → Suricata 룰 (순수 코드, LLM 없음)
 │  llm/render_report.py            코드가 표 주입 + LLM 서술 1콜 → 한국어 MD → [ o / x ]
 ▼
 │  scripts/score.py --compare      [코드-only / +LLM] recall·precision 표 (answers/truth)
```

Kaggle T4×2에서 `kaggle/run_pipeline.ipynb`(항상 Run All) 하나로 전 과정이 돈다. 모듈 상세는 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## 설계 원칙 — 왜 이렇게 생겼나

1. **코드가 심판, LLM은 판독기 + 이야기꾼.** 로컬 SLM은 IP를 베끼다 망가뜨리고, 없는 걸 지어내고, 정상 CDN을 C2로 넣는다.
   그래서 정답이 하나뿐인 값(IP·도메인·해시·호스트 신원)은 코드가 채우고 대조한다. 실측 결과 **행동 신호의 판단(죽은 비콘·DGA)도
   코드가 더 정확했다** — LLM의 증명된 가치는 시그니처 없는 공격 패턴 판독(Shellshock 7출처, 시그니처 0)과 한국어 서술이다.
2. **코드가 아는 답은 시험 전에 준다.** 위협/정황 구분(`threat_class`)·정상 대비 편차(`deviations`)·검색 접미사·비콘 규칙성을
   evidence 단계에서 계산해 모델에 준다. 모델을 severity 숫자에 속게 두고 뒤에서 수습하지 않는다.
3. **정상을 알고 편차만 본다.** 노이즈 억제는 프롬프트가 아니라 코드의 일이다(`baseline.py`).
4. **차단 룰은 절대 LLM으로 만들지 않는다.** 정제된 IOC를 LLM에 다시 주면 재오염된다.
5. **바닥이 1급 시민이다.** 모든 성능 표는 [코드-only / +LLM] 두 행. LLM 행만 있는 숫자는 인용하지 않는다.
6. **규칙에 케이스 이름을 넣지 않는다.** 승격기·가드는 반례 테스트 쌍(승격 1 + 비승격 N)으로 잠근다. 레드팀 페르소나가 오버핏을 심사한다.
7. **실측 없이 주장하지 않는다.** think 레벨(무효)·작은 모델(탈락)·컨텍스트 확대(오답) 전부 재고 나서 버렸다.

## 실측 하이라이트 (q2, qwen3.8:27b, T4×2, 2026-09-09)

| 행 | verdict | iocR | iocP | domR | LLM 자력 발견 | 시간 |
|---|---|---|---|---|---|---|
| 코드 바닥 | suspicious | **0.80** | 1.00 | 0.17 | — | 2s |
| 코드 바닥, 알럿 0 | no_incident | 0.00 | – | 0.00 | — | 1s |
| +LLM | confirmed ✓ | **0.90** | 1.00 | 0.17 | C2 1개 + DGA 부모 | 21분 |
| +LLM, 알럿 0 | suspicious | 0.20 | 1.00 | 0.17 | 0 (전부 코드 승격기) | 22분 |

- 정밀도 1.00, 환각 0. LLM은 알럿 위에서 IOC +0.10과 감염 호스트 판정, 16줄 타임라인을 얹는다.
- **시그니처 제거 ablation**("LLM이 필요한가"): 알럿을 빼면 LLM은 Poweliks 감염을 못 봤지만(감염 호스트 0명) **관찰은 정확**했고
  (base64 응답·랜덤 경로·DGA·죽은 비콘 전부 타임라인에), Shellshock 공격자 7개를 시그니처 0으로 판독했다. 코드 바닥은 알럿 없이
  no_incident — 행동 승격기가 알럿 게이트 뒤에 갇혀 있다(다음 티켓).
- 시간: prefill 230 tok/s, **decode 12.8 tok/s**, 사고가 벽시계의 ~75%. think 레벨 xhigh↔medium 무차이. 30B MoE(활성 3B)는 IOC 기여 0 + 서술 오류 3건으로 탈락.
- 산출물 원본: [docs/results/](docs/results/) (reports/는 gitignore라 복원 사본).

## 알려진 한계와 다음 단계

전체 리뷰(감사 4 + 레드팀 1, 2026-09): [docs/REVIEW-2026-09.md](docs/REVIEW-2026-09.md). 리뷰어가 먼저 볼 것 3가지:

1. **룰 방향** — 인바운드 공격자가 `drop ip $HOME_NET -> X`(아웃바운드 전용)로만 막힌다. iocs에 attacker 버킷이 없어서 프롬프트·truth·채점기까지 같은 오분류.
2. **그라운딩 구멍** — `attacks[].actor`는 관측집합 대조 없이 룰이 된다. 인바운드 공격자 IP는 관측집합에 없어 "환각"으로 기각됐다가 승격기가 재삽입한다.
3. **가드·프롬프트가 정답을 지운다** — 비-C2 technique의 target 삭제가 delivery·랜딩 도메인을 없애고, "광고=서술만" 지시가 클릭사기 도메인을 격추한다.

측정 쪽: q2는 승격기·채점기·truth가 같은 날 진화한 개발 케이스(훈련=시험), truth는 evidence에서 후보를 뽑아 확정(파이프라인이
못 본 IOC는 정답에도 없음), 무혐의 케이스 0(오경보율 측정 불가), 바닥 verdict는 설계상 항상 0. 우선순위 TOP 10과 크기는 리뷰 문서에.

## 실행

### 로컬 (GPU 없이 가드·정책·채점 반복 가능)
```bash
./setup.sh                                           # 최초 1회 (MODEL 환경변수로 모델 지정)
./scripts/extract_log.sh pcaps/<파일>.pcap            # → output/<name>/{suricata,zeek}
python3 scripts/build_evidence.py <name>             # → output/<name>/evidence.json
python3 scripts/build_evidence.py <name> --noalert   # (ablation) → output/<name>-noalert/
cd llm && python3 test_guards.py && python3 test_views.py   # 49 tests, 1초, ollama 불필요
cd llm && python3 run.py <name> --floor              # 코드-only 바닥 → reports/floor/<name>.json
cd llm && python3 run.py <name> [--fresh|--replay]   # LLM 분석 → reports/<name>.json (auto: evidence 동일하면 캐시 재생)
python3 scripts/make_policy.py <name> --validate     # → reports/<name>.rules (suricata -T)
cd llm && python3 render_report.py <name>            # → reports/<name>.md
python3 scripts/score.py --compare reports/floor reports
```

### Kaggle
Settings → Internet ON + GPU T4×2, pcap 데이터셋 Add Input, `kaggle/run_pipeline.ipynb` **항상 Run All**. 모든 셀이 멱등이라
재실행 시작점 개념이 없다(설치·pull은 몇 초에 건너뜀, forensic은 evidence 동일하면 캐시 재생). 시크릿 없이도 완전 동작
(GH_PAT: 케이스별 체크포인트 push, KAGGLE_*: 모델 캐시 데이터셋 — 둘 다 선택).

### 설정 — `.env` 한 파일
`MODEL`(공식 표준 태그만) / `NUM_CTX` / `THINK`(true·false·low·medium·high) / `THINK_NARRATIVE` / 샘플링 / `NUM_PREDICT`.
프롬프트는 `llm/prompts/*.md`. 코드 안 건드리고 튜닝한다.

## 디렉터리

```
setup.sh                     조용·멱등 설치(suricata/zeek/ollama/모델/pip), 캐시 데이터셋 복원
.env                         설정 단일 소스
scripts/
  extract_log.sh, run_suricata.sh, run_zeek.sh      pcap → 로그
  hash-files.zeek, http-bodies.zeek                  Zeek 확장(sha256 강제, http 본문·헤더)
  build_evidence.py                                  로그 → evidence.json (결정론), --noalert
  baseline.py                                        정상/편차 엔진, threat_class(), 검색 접미사
  make_policy.py                                     reports/*.json → Suricata 룰 (순수 코드)
  score.py                                           truth 대비 recall/precision, --compare
  make_truth.py, gen_attack_pcap.py                  truth 초안 생성기, 합성 공격 pcap
llm/
  config.py                  .env 로더 + JSON 스키마 + 프롬프트 로드
  tools.py                   evidence 읽기 API(뷰 강등, 관측집합, 해시 조인)
  run.py                     code_triage → forensic(캐시) → 가드(PASSES) → 승급 → LLM델타 / --floor
  render_report.py           한국어 MD 보고서
  prompts/forensic.md, triage.md
  test_guards.py, test_views.py
kaggle/run_pipeline.ipynb    Kaggle 러너(7셀)
answers/truth/               채점용 정답 원자(JSON) + q2.notes.md(패킷 레벨 근거)
docs/                        ARCHITECTURE · HISTORY · MEASUREMENTS · REVIEW-2026-09 · results/
output/, reports/  (gitignore)  로그·evidence / 분석 json·rules·md
```

## 문서

| 문서 | 내용 |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 모듈 단위 동작(evidence 필드, 캡 정책, 뷰 단계, PASSES 표, 정책·보고서·채점·노트북 셀) |
| [docs/HISTORY.md](docs/HISTORY.md) | 개발 여정 — 8단계, 반복된 고민 7가지, 되돌린 시도들 (커밋 해시 포함) |
| [docs/MEASUREMENTS.md](docs/MEASUREMENTS.md) | 실측 원장 — q2 4행 표, 베이크오프, 시간 분해, 결정론 계층 교차 검증, 채점기 한계, 인벤토리 |
| [docs/REVIEW-2026-09.md](docs/REVIEW-2026-09.md) | 전체 리뷰 — 감사 4 + 레드팀 검증, 구조 판정, 우선순위 TOP 10 |
| [docs/results/](docs/results/) | 실제 산출물 사본(분석 JSON·보고서 MD·룰), 커밋·모델·설정·계측 스탬프 |
| [answers/truth/q2.notes.md](answers/truth/q2.notes.md) | q2 패킷 레벨 재분석 근거(pwned.se=검색 접미사, 94.242=죽은 비콘, 해시 2개 정상) |

## 검증 이력 (요약)

- **2026-07-09 q1/q2** 첫 완주. 웹서버 익스플로잇은 시도·실패(404·콜백 없음), 실제 감염은 알럿 약한 쪽(클릭사기 CnC·애드웨어).
- **2026-08-04** MTA 공식 정답 4건 + 합성 웹공격 케이스, baseline/편차 엔진(6케이스 결정론 검증, MS 텔레메트리 오탐 20→0).
- **2026-09-02** q2 패킷 레벨 재분석 → truth v2.1(검색 접미사·죽은 비콘·정상 해시). 레드팀 판결 → `verdict-baseline` 태그(50ce68c),
  precision + 코드-only 바닥, 승격기 2종(반례 테스트 쌍).
- **2026-09-03~09** 30B MoE 베이크오프 탈락, 시그니처 제거 ablation 첫 데이터, 전체 리뷰.

자세한 흐름은 [docs/HISTORY.md](docs/HISTORY.md).
