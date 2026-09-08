# auto_packet_analyze_v3

pcap 하나를 넣으면 **자동으로 네트워크 포렌식 분석 → 차단 정책(Suricata 룰) → 한글 보고서**까지 만들고,
사람은 마지막에 **보고서를 읽고 차단 적용 여부(o/x)만** 고른다. 핵심 목표는 **인간 개입의 최소화**.

Suricata/Zeek 로 pcap에서 로그를 뽑고, 로컬 LLM(Ollama)이 그 로그만 근거로 피해자·공격자·공격행위·타임라인을
판단한다. **외부 위협인텔은 안 쓴다** — pcap + 시그니처 + 행동만으로 얼마나 정확한가가 이 프로젝트의 평가 기준.

---

## 전체 파이프라인

```
pcap
 │  scripts/extract_log.sh            (Suricata + Zeek)
 ▼
output/<name>/{suricata/eve.json, zeek/*.log}
 │  scripts/build_evidence.py         (정규화·압축, 결정론적, 판단 없음)
 ▼
output/<name>/evidence.json           ← "tier1 근거 번들"
 │  llm/run.py                        (LLM 분석 + 코드 안전가드)
 ▼
reports/<name>.json                   ← 분석 결과(구조화 JSON)
 │  scripts/make_policy.py            (코드, chat 없음)
 ▼
reports/<name>.rules                  ← Suricata 차단 룰
 │  llm/render_report.py              (코드가 표 주입 + LLM 서술 1콜)
 ▼
reports/<name>.md                     ← 최종 한글 보고서 → 사람이 [ o / x ]
```

Kaggle에서는 `kaggle/run_pipeline.ipynb` 가 위 전 과정을 pcap마다 자동으로 돈다.

---

## 핵심 설계 원칙: **"코드가 팩트, LLM이 판단"**

LLM(특히 로컬 26~27B)은 IP/도메인/해시를 **베끼다 손상**시키거나(`65.6_35.141`), **누락**하거나, 없는 걸 **지어낸다**.
그래서 **정답이 하나뿐이고 evidence에 존재하는 값은 전부 코드가 채우고**, LLM은 **열린 판단**(사건이냐 아니냐,
어느 멀웨어냐, 이게 유출이냐)과 **서술**만 맡는다.

| 코드가 소유 (팩트) | LLM이 소유 (판단) |
|---|---|
| mac / hostname / username (evidence 조인) | verdict (사건/무혐의) |
| iocs.hashes (파일에서 추출 + 업데이트인프라 오탐 제외) | 멀웨어 패밀리 attribution (시그니처 기반) |
| IOC 그라운딩 (evidence 관측집합 대조, 오염·환각 제거) | 유출 판단 (맥락 기반) |
| 내부 자산 / 공격 표적 차단 제외 (자폭 방지) | 타임라인 시나리오, 개요·권고 서술 |
| 차단 룰 생성 (make_policy) | |

**코드가 아는 답은 시험 전에 준다.** 위협/정황 구분(`threat_class`)은 코드가 evidence 단계에서
알럿마다 스탬프해 LLM 에게 준다 — 코드가 답을 알면서 모델을 severity 숫자에 속게 두고 뒤에서
가드로 수습하던 구조(q2 에서 Dropbox/Skype sev1 이 C2 로)를 뿌리에서 끊는다.

또 하나: **차단 룰은 절대 LLM(chat)으로 안 만든다.** 이미 정제된 IOC를 LLM에 다시 주면 재오염되므로,
`make_policy.py`가 **순수 코드로** iocs를 룰 템플릿에 끼워넣는다.

> ⚠️ **참고**: 분석 경로는 tool-calling을 **안 쓴다.** Ollama에서 `format=`(JSON 스키마 강제)와 `tools=`가
> 공존 불가라, tier1 근거를 메시지에 **직접 주입 + `format=REPORT_SCHEMA` 로 JSON 강제**하는 구조다.
> (`tools.py`의 함수들은 "tool"이 아니라 evidence를 읽어주는 **코드 API**다.)

---

## 디렉터리 구조

```
setup.sh                     # 조용·멱등 설치(suricata/zeek/ollama/모델/pip) — 상세는 setup.log, LLM 스모크 없음
.env                         # MODEL / NUM_CTX / TEMPERATURE / SEED (설정 단일 소스)
scripts/
  run_suricata.sh            # pcap → suricata eve.json
  run_zeek.sh                # pcap → zeek NDJSON (네이티브 없으면 docker zeek 폴백)
  extract_log.sh <pcap>      # 위 둘을 한번에 → output/<name>/{suricata,zeek}
  build_evidence.py <name>   # 로그 → output/<name>/evidence.json (tier1 번들, 알럿마다 threat_class 스탬프)
  baseline.py                # 결정론 편차 엔진 + threat_class() (시그니처 위협분류의 단일 소스)
  make_policy.py <name>      # reports/<name>.json → reports/<name>.rules (Suricata)
llm/
  config.py                  # .env 로더(MODEL/NUM_CTX/THINK/샘플링) + REPORT/VERDICT 스키마 + 프롬프트 로드
  tools.py                   # Tools 클래스: evidence.json 을 읽어주는 코드 API
  run.py                     # 분석 단계: triage → forensic → 가드(CaseContext + PASSES) → reports/<name>.json
  test_guards.py             # 가드 유닛테스트 (LLM/GPU 불필요, 1초) — 노트북이 파이프라인 전에 돌림
  render_report.py           # reports/<name>.json + .rules → reports/<name>.md (한글)
  prompts/
    triage.md                # triage 시스템 프롬프트
    forensic.md              # forensic 시스템 프롬프트
  test.py                    # tool-calling 스모크(레거시, 분석 경로 미사용)
kaggle/
  run_pipeline.ipynb         # Kaggle 러너 (전 단계 자동)
output/    (gitignore)       # pcap별 로그 + evidence.json
reports/   (gitignore)       # 분석 json + .rules + .md (생성물)
```

---

## 단계별 상세

### 1) 로그 추출 — `scripts/extract_log.sh <pcap>`
`run_suricata.sh`(→ `eve.json`) + `run_zeek.sh`(→ conn/dns/http/dce_rpc/smb/kerberos/... NDJSON)를 한 번에.
zeek는 네이티브가 없으면 **docker `zeek/zeek:latest`** 로 폴백. 출력: `output/<name>/{suricata,zeek}`.

### 2) 근거 번들 — `scripts/build_evidence.py <name>`
로그를 **결정론적으로** 정규화·압축해 `evidence.json` 하나로. **판단(휴리스틱)은 여기서 안 한다.** 주요 필드:
- `meta` (capture 창, duration, flow 수) · `hosts` (ip/mac/hostname/username/role/ad_domain, first/last_ts)
- `alerts` (Suricata 시그니처, severity, **`threat_class`**(threat/rat/benign/unclassified — 코드 분류, 숫자 severity 불신), count, src/dst) · `external` (`ips`/`domains`/`sni`/**`http`**)
- `files` (해시·mime, 서빙 uid 조인) · `lateral_movement` (dst 역할별 dcerpc_ops/smb_writes)
- `anomalies` (무시그니처 행동: 비콘 지터, 업로드 비율, no-DNS 직결, odd-port, 역할이탈, DNS 엔트로피)

핵심: **http 요청 URI를 evidence로 올린다** — path traversal/웹공격은 시그니처가 없어도 URI에 드러나므로.

### 3) 분석 — `llm/run.py <name>` (아래 "run.py 상세" 참조)
`reports/<name>.json` 저장. 룰생성(`make_policy`)·보고서(`render_report`)의 공통 입력.

### 4) 차단 정책 — `scripts/make_policy.py <name> [--validate]`
**순수 코드.** `reports/<name>.json`의 iocs를 Suricata 룰로:
- `c2/delivery/exfil` + 외부 공격자 → `drop ip $HOME_NET -> <ip>`
- `domains` → `drop dns`(dns.query) + `drop tls`(tls.sni)
- 내부 공격자(actor_scope=internal) → `drop ip <host> -> any` (호스트 격리)
- 표적(피격자)·내부 자산은 이미 상류에서 iocs에서 빠져 있어 **자기 서버 자폭 안 함**
- `--validate` 면 `suricata -T` 로 문법 검증. sid 는 `1000000+`. (해시 룰은 보류)

### 5) 최종 보고서 — `llm/render_report.py <name>`
`reports/<name>.md`(한글). **코드가 사실 표를 주입**(피해자/IOC/타임라인/룰), **LLM은 서술만**(개요/시나리오/권고,
`format`강제 1콜). ollama 없으면 서술을 스텁 처리(로컬에서 표/룰 검증 가능). 끝에 **`[ o / x ]`** — 사람의 유일한 결정점.

---

## `llm/run.py` 상세 — 분석 단계

`main()` 흐름: `triage → (사건이면) forensic → apply_guards(PASSES) → 저장`. 결과 JSON 에 `pipeline_status`
(`ok` / `forensic_parse_failed`)가 있어 부분 산출물과 완전 산출물을 채점에서 구분할 수 있다.

**LLM 호출 (판단)** — 둘 다 tier1 근거 주입 + `format=` 스키마 강제 단일 chat, `think=THINK`(.env):

| 함수 | 역할 |
|---|---|
| `triage(tools)` | 1차 판정 `no_incident`/`suspicious`/`confirmed`. `no_incident`면 분석 안 감(무혐의를 사건으로 프레이밍하는 것 차단). |
| `forensic(tools)` | 본 분석 → victims/iocs/timeline/patient_zero/attacks 등 구조화 JSON. |

**코드 가드 (팩트)** — `CaseContext` 가 케이스의 집합 장부(내부IP·AD존·외부관측IP·공격표적·그라운딩 기준집합)를
**한 번만** 계산해 모든 가드에 공유한다(전엔 가드 8개가 각자 복붙 계산 — 판정 기준을 바꾸면 8곳을 고쳐야 했다).
가드는 `PASSES` 리스트 순서대로 돈다 — **순서가 곧 규칙**: 정리/제거 구간이 끝난 뒤 승격 구간.

| PASSES 순서 | 역할 |
|---|---|
| `attach_identity` | victims 의 mac/hostname/username/role 을 evidence 조인으로 코드가 확정. 구분자 손상 IP(`10.6_15.187`) 재조립, 장식 제거. |
| `demote_infra_victims` | 정상 AD 인증을 받는 DC/DNS 를 `compromised`→`infrastructure` (격리 자폭 방지). 위협 alert 의 출발지인 DC 는 그대로 둠. |
| `attach_hashes` | `iocs.hashes` 를 evidence files 에서 코드가 채움. 업데이트 인프라 서빙 실행파일은 제외(`_excluded_benign_hashes`). |
| `ground_iocs` | iocs 의 IP/도메인을 관측집합과 대조 — 미관측(환각)·내부 자산·TLD 기각, 버킷 오배치 도메인 salvage. `_rejected_iocs`. |
| `annotate_attacks` | attacks 의 actor/target scope 확정, 표적(피격자)을 iocs 에서 제거. `_removed_attack_targets`. |
| ── 승격 구간 ── | (제거 뒤여야 승격분이 도로 안 지워짐) |
| `attach_iocs_from_alerts` | `threat_class` 가 threat/rat 인 alert 의 외부 관측 IP → c2. benign(Dropbox/Skype sev1)은 승격 안 됨. |
| `attach_iocs_from_dns` | 의심 TLD(.gq/.cc/.xyz…) 도메인 중 피해자가 실제 접속한 IP 로 해석된 것 + 그 IP 승격 (HTTPS-only 후속 C2). |
| `attach_inbound_threat_ips` | 인바운드 위협 alert 의 외부 출발지(우리 서버를 때리는 공격자) → c2. |

새 가드 추가 = 함수 하나(`(analysis, ctx)`) + `PASSES` 에서 자리 정하기 + `test_guards.py` 에 케이스 하나.

> 왜 가드가 이렇게 많나: 로컬 SLM이 팩트를 계속 망쳐서, **매 실패 지점을 코드로 하나씩 받아낸** 결과.
> 그래서 모델을 바꿔도(gemma↔qwen) 팩트는 안 흔들리고 **판단 품질 차이만 드러난다.**

---

## `llm/tools.py` 상세 — evidence 읽어주는 코드 API

`Tools(name)` 은 `output/<name>/evidence.json` 을 로드. 크게 두 종류:

**(A) tier1 근거 getter — run.py 가 LLM 메시지에 주입하는 것들**
| 메서드 | 반환 |
|---|---|
| `get_meta()` | capture 창/duration/flow 수 (짧은 캡처면 비콘 휴리스틱 불신용) |
| `get_hosts_info()` | 전 호스트 ip/mac/hostname/username/role/ad_domain + 활동창 |
| `get_alerts()` | Suricata 알럿 전량(시그니처/severity/**threat_class**/count/src/dst) — 모델은 severity 가 아니라 threat_class 로 위협을 가른다 |
| `get_external()` | **알럿에 엮인** 외부 ip/도메인 + sni (배경 CDN/텔레메트리 노이즈 제거) |
| `get_http()` / `http_view(level)` | 웹 요청 전량(method/url/status/UA/body/헤더). `http_view` 는 예산 초과 시에만 쓰는 단계적 강등 뷰(신호 행 보존, 접은 건 `_view` 로 명시) — `_tier1` 이 예산에 맞는 최저 level 을 고른다 |
| `get_files()` | 멀웨어 후보 파일(실행/압축/스크립트)은 전문, 나머지는 mime별 요약 |
| `get_lateral_movement()` | 내부↔내부: dst 역할별 dcerpc_ops/smb_shares/smb_writes (정찰 vs 실행 구분 재료) |
| `get_anomalies()` | 무시그니처 행동 측정치(비콘/업로드비율/no-dns/odd-port/역할이탈/DNS엔트로피) |
| `get_signals()` | RPC 기법 라벨·zeek weird·프로토콜 요약·존재 로그 목록 |

> ⚠️ **`get_external()` 필터 한계**: "알럿에 엮인 IP만 통과" 규칙은 benign 알럿(Dropbox·Skype)이 참조하는 IP도
> 통과시킨다 — 다만 이제 각 알럿에 `threat_class` 가 붙어 모델이 구분할 수 있고, 코드 승격기는 threat/rat 만 올린다.
> 반대로 알럿이 없는 IOC(DGA 도메인, 애드웨어)는 `background_domains` 로 빠진다(의심 TLD 는 `attach_iocs_from_dns` 가 구제).

**(B) 코드 전용 헬퍼 — 가드가 쓰는 것들 (LLM 미노출)**
| 메서드 | 용도 |
|---|---|
| `malware_candidate_hashes()` | 멀웨어 해시를 서빙호스트로 악성/정상 분리 (attach_hashes) |
| `serving_host_for_hash(sha)` | files→http uid 조인으로 그 해시를 서빙한 호스트 |
| `observed_iocs()` | 그라운딩 기준집합 = evidence의 **"외부 관측" IP/도메인/해시**. 내부 자산(호스트IP·AD존·내부전용 해석 이름)은 **원천 제외** (ground_iocs 가 이걸로 대조) |

`get_host_info`/`get_alerts_by_severity`/`search_external` 은 단건 조회용(레거시 tool 스모크, 분석 경로 미사용).

---

## `llm/config.py` — 설정 단일 소스
리포 루트 `.env` 를 읽어 노출: `MODEL`, `NUM_CTX`, `THINK`(false/true/low/medium/high — 추론 강도), `OPTS`(temperature/top_p/top_k/seed/num_ctx/num_predict/num_batch), `VERDICT_SCHEMA`,
`REPORT_SCHEMA`(둘 다 ollama `format` 강제용), `SYSTEM_PROMPT_TRIAGE/FORENSIC`(=`prompts/*.md`).
**프롬프트는 코드 아니라 `.md` 파일**, **설정은 `.env` 한 줄** — 코드 안 건드리고 튜닝.

---

## 실행

### 로컬
```bash
./setup.sh                                       # 최초 1회
./scripts/extract_log.sh pcaps/<파일>.pcap        # → output/<name>/{suricata,zeek}
python3 scripts/build_evidence.py <name>          # → output/<name>/evidence.json
cd llm && python3 test_guards.py                  # 가드 유닛테스트 (ollama 불필요, 1초)
python3 scripts/build_evidence.py <name> --noalert   # (ablation) 알럿만 0 인 output/<name>-noalert/ — 아래 참고
cd llm && python3 run.py <name>                   # → reports/<name>.json  (기본 auto: evidence 동일하면
                                                  #   forensic 캐시 재생 = LLM 생략. --fresh 강제호출 / --replay LLM 없이 캐시만)
cd .. && python3 scripts/make_policy.py <name> --validate   # → reports/<name>.rules
cd llm && python3 render_report.py <name>         # → reports/<name>.md
```

**시그니처 제거 ablation** (`--noalert`): 같은 Zeek 로그에서 Suricata 알럿만 0 으로 만든 `<name>-noalert`
케이스를 만들어 원본 truth 로 채점한다 — "시그니처 없는(미지의) 위협에서 행동 신호만으로 코드 바닥/LLM 이
무엇을 잡나"를 4행(floor / floor-noalert / +LLM / +LLM-noalert)으로 잰다. 노트북 `ABLATION=True` 가 자동으로 병행.
첫 실측(q2, 코드-only): 알럿 있음 iocR 0.80 → 알럿 없음 **no_incident, IOC 0** — 죽은 비콘·의심 TLD 승격기는
행동 신호인데 `code_triage` 가 알럿/해시로만 사건 바닥을 정해 승격기까지 못 간다(후속 티켓, LLM 행 결과 뒤 결정).

### Kaggle
`kaggle/run_pipeline.ipynb` — Settings에서 **Internet ON + GPU**, pcap 데이터셋 Add Input, **항상 Run All**.
모든 셀이 멱등(설치·pull 은 돼 있으면 몇 초에 건너뜀, forensic 은 evidence 동일하면 캐시 재생)이라 재실행 시작점 개념이 없다.

---

## 모델 교체 (bakeoff)

`.env` 의 `MODEL=` 한 줄만 바꾸면 됨(config.py 단일 소스). 요건은 **tool 지원이 아니라 `format`(구조화 출력) 지원** —
llama.cpp 그래머라 대부분 모델 가능.

**하드웨어 현실 (2×T4 = 16GB×2, NVLink 없음):**
- **한 카드(16GB)에 통째로 드는 모델**이 스윗스팟 — split 안 해서 빠름.
- 27B(≈18GB)는 두 카드에 쪼개져 PCIe 오버헤드 → **pcap당 5분+** (느리지만 배치 포렌식엔 감내 가능).
- 후보: `gemma3:27b`, `mistral-small3.2:24b`, `phi4:14b`(빠름). 70B·qwen/deepseek 제외.
- 안 뜨면(OOM) `.env` `NUM_CTX` 낮추기.

**qwen3.8:27b (현재, `-mtp-q4_K_M` 태그)**: 동급 오픈웨이트 1위(AA Index 52)인데 **추론(thinking) 켠 점수**다.
- `.env THINK` 로 추론 강도 조절 — **ollama 가 qwen3.8 전용 렌더러(`model/renderers/qwen35.go`)로 레벨을
  지원한다** (`think="low"/"medium"/"high"` 문자열). reasoning_effort 의 정체는 토큰 예산이 아니라 템플릿에
  끼워넣는 지침 문장: xhigh="철저히 더블체크"(최대 사고), **medium=지침 없음**(본연 판단), low="빨리 결론".
  실측(커뮤니티 벤치): 복잡 과제에서 medium 은 토큰 40~60% 절감·완성도 소폭↓, low 는 토큰 폭증+자가검증
  루프라 포렌식 금지. `THINK=true`(bool)는 xhigh 로 매핑 — 그동안 최대 과잉사고로 돌았던 원인.
  현재 기본 `THINK=medium`, 직전 xhigh 결과(forensic_raw 캐시)와 truth 로 A/B 중.
  끄면(`false`) 판단력 급감(광고를 IOC 로, q2 실측) — 금지.
- ollama 버그 이력: think=false 면 `format` 스키마가 조용히 무시됨(#14645/#15260). 노트북 진단 셀이 매 세션
  `format 강제 OK` 를 확인한다.
- 샘플링은 모델카드 권장(thinking 1.0/0.95). MTP 는 무손실(메인 모델 검증)이라 품질 요인 아님.
- T4 16GB×2 에 18GB + 65k KV 를 넣으려면 KV 양자화 필수 — 노트북 `KV_TYPE`(q8_0 기본, 스필 시 q4_0).

**비교법**: 같은 pcap 세트로 각 모델을 돌려 결과를 나란히 비교. 코드가 팩트를 받쳐서 **판단 품질만 순수 비교**됨.

---

## 검증 이력

**2026-07-09 — q1 / q2** (FIRST-2015 계열 허니넷, 같은 망 24h 캡처 이틀치). 처음 보는 pcap에 전 단계(추출→evidence→분석→룰→보고서) 완주. 정답:
- 웹서버 192.168.0.2 대상 인터넷 익스플로잇은 **시도·실패**: q1 PHP-CGI 인자주입 → 404·콜백없음, q2 Shellshock 802건 → 404·콜백없음.
- 실제 감염은 알럿이 약하거나 없는 쪽: 192.168.0.53 클릭사기 CnC(88.214.241.199) + DGA(`*service*online*.org`), 192.168.0.54 애드웨어(technologieduluth/wajam, 알럿 0건).
- 오탐 주의: `pwned.se` 는 LAN DNS 검색 접미사(전부 NXDOMAIN), NVIDIA PE 다운로드는 정상 파일.

이 실행에서 아래 "알려진 한계"의 1~4번을 확인함.

---

**2026-09-02 — q2 패킷 레벨 재분석** (근거 전문: `answers/truth/q2.notes.md`, truth v2 로 정정):
- **pwned.se 는 DNS 터널이 아니라 LAN DHCP 검색 접미사** — 1,045건 전부 NXDOMAIN(내부 GW 응답), 비감염
  호스트도 질의(wpad/isatap/자기명). v1 truth 의 "터널 백도어" 라벨 정정 (README 초기 관찰이 옳았음).
- 신규 IOC: **94.242.254.208 = 죽은 주 C2 비콘**(13초 간격 773회 전부 S0 무응답, 24h) — 어떤 보고서에도 없었음.
- searchl.org/2hood.eu 는 DNS 무질의(직결+Host 헤더) → observed_iocs 갭 실증, http host 포함으로 수정.
- 해시 2개(NVIDIA 서명 드라이버·AOL SWF)는 카빙 바이너리 검증으로 정상 확정 → BENIGN_SERVING 확장.
- Wajam 애드웨어는 .53 이 아니라 **.54** (http.log 출발지 전수 확인).
- .2 웹공격 7출처 전건 실패 확정: 200 응답은 GET|HEAD / 7건뿐, 페이로드 서버 6곳 접촉 0, .2 의 DNS 질의 0.

## 알려진 한계 / TODO

**2026-07-09 q1/q2 에서 확인 (코드로 해결 가능):**
1. **성공/시도 미구분** — 인바운드 웹 익스플로잇이 4xx 응답 + 콜백 부재면 실패인데, 모델은 sev1 알럿만 보고 `confirmed`·`compromised`로 판정. → http.log 응답코드 + conn.log 콜백유무를 코드가 확인해 "시도(실패)" 판정, 그 호스트에 confirmed 금지.
2. **정상 CDN/광고를 IOC로** — (코드 승격기 쪽은 해결) `threat_class` 게이트로 Dropbox/Skype sev1 이 c2 에 안 들어간다.
   (LLM 쪽은 남음) 모델이 직접 iocs 에 넣은 **관측된** 광고 도메인·구글/페북 exfil 은 `ground_iocs` 가 '존재'만 대조하므로 통과한다
   (q2: 도메인 28개 중 25개가 광고, exfil 3개가 페북/구글). 프롬프트에 threat_class/baseline 지시를 넣었고, 남은 건
   **score.py 에 precision(iocP/domP) 추가** — 지금 채점표는 recall 뿐이라 과차단이 어느 숫자에도 안 잡힌다.
3. **tier1 컨텍스트 초과** — (해결) q2 tier1 은 qwen 토크나이저(숫자 1자=1토큰) 기준 **136k 토큰**이었고, ollama 는 안 들어가는 user 메시지를 잘라주지 않고 통째로 버린다("no user query found", 12분 태운 뒤). 두 층에서 고쳤다:
   - **evidence 캡을 시간순 → 신호 우선 + tier 별 최소 할당**(build_evidence `capped`): 인바운드(공격면) > 위협 alert 연결 > 이상행동 목적지 > 의심 TLD > 웹공격 패턴 > 시간순. 시간순 캡은 24h 캡처의 첫 75분만 싣고 Shellshock 865건을 버렸었다. tier 별 탈락 건수가 `_truncation.*_by_tier` 에 남는다. 편차 랭킹은 캡 전 전량으로 계산.
   - **LLM 뷰 단계적 강등**(tools `http_view`, run `_tier1`): 예산(NUM_CTX×0.6 forensic / ×0.25 triage) 안이면 **level 0 = 전량(오늘과 동일 — 소형 5케이스 실측 동일)**. 넘칠 때만 '신호 없는 행'부터 지문→접기→건수로 줄이고, 신호 행(인바운드·위협alert·편차·이상행동·의심TLD·웹패턴)은 level 3 까지 전량, level 4 에서 페이로드 기준 접기(스프레이 = 같은 페이로드 × 여러 경로 → 표본 3 + 개수). 접은 건 `_view` 로 모델에 알린다. 최대 강등 후에도 넘치면 **호출 전** 실패. q2: 136k → 25k, Shellshock/터널/C2 전부 생존. 계약은 `test_views.py` 가 잠근다(처음 보는 인바운드 페이로드가 모든 단계에서 생존).
   - 남은 것: 인코딩(base64/url/gzip)은 여전히 코드가 안 풀어준다.
4. **근거(grounds) 영어** — `forensic.md` 가 한글을 강제하는 필드가 `timeline.event`/`assessment` 둘뿐 → `grounds` 는 영어 evidence를 미러링. → 한글 강제 목록에 `grounds` 추가.

5. **S0 죽은-비콘 미승격** — 무응답(S0) 외부 직결이 수백 회·수 시간 반복되는 죽은 C2 비콘(q2 의
   94.242.254.208)을 IOC 로 올리는 결정론 승격기 없음. 임계값(횟수·기간·주기성·DNS 부재) 설계 +
   교차 케이스 오탐 검증 후 추가할 것 (P2P/게임 재시도와의 구분 필요).

**기존 한계:**
- **모델 천장**: 로컬 26~27B는 run마다 결과가 달라지고(비결정), 덜 뽑거나(도메인 누락) 과하게 넣음(정당 서비스). 코드 가드로 팩트는 지키지만 recall/판단은 모델 몫.
- **CDN 과차단**: 악성 도메인이 공유 엣지 뒤에 있으면 IP가 CDN 대역으로 풀려, 그 IP를 c2에 넣으면 룰이 CDN 전체를 차단. make_policy `_is_cdn`/`_CDN_NETS` 가 **Cloudflare/Fastly 대역은 IP-drop에서 제외(구현됨)**, 도메인 룰(dns/tls)로 대체. 다만 대역이 Cloudflare/Fastly 한정이라 Dropbox(108.160)·Google·Facebook·Skype·NVIDIA 엣지는 못 거르고, `attach_iocs_from_alerts` 가 severity 1 INFO/CHAT 알럿의 이 IP들을 c2에 넣음. → `_CDN_NETS` 확장 또는 alert 카테고리 게이팅 필요.
- **서술이 분석 에러를 증폭**: render_report는 분석을 충실히 한글로 풀 뿐, 분석이 틀리면 자신만만하게 틀린 보고서가 됨(예: 근거 없는 측면이동 서술). → adversarial 검증층(red-team) 미구현.
- **암호화/외부인텔 한계**: TLS 내부 payload·DoH·정상 사이트 악용(github/maven 호스팅) 등은 pcap+시그니처만으론 불가 — 천장이지 버그 아님.
- **검증셋 좁음**: MTA류 교육용 pcap 위주. 실제 기업망(대용량·멀티호스트·시끄러움) 미검증.
