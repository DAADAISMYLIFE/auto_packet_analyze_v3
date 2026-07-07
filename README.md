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

또 하나: **차단 룰은 절대 LLM(chat)으로 안 만든다.** 이미 정제된 IOC를 LLM에 다시 주면 재오염되므로,
`make_policy.py`가 **순수 코드로** iocs를 룰 템플릿에 끼워넣는다.

> ⚠️ **참고**: 분석 경로는 tool-calling을 **안 쓴다.** Ollama에서 `format=`(JSON 스키마 강제)와 `tools=`가
> 공존 불가라, tier1 근거를 메시지에 **직접 주입 + `format=REPORT_SCHEMA` 로 JSON 강제**하는 구조다.
> (`tools.py`의 함수들은 "tool"이 아니라 evidence를 읽어주는 **코드 API**다.)

---

## 디렉터리 구조

```
setup.sh                     # suricata/zeek/ollama 설치 + 모델 pull
.env                         # MODEL / NUM_CTX / TEMPERATURE / SEED (설정 단일 소스)
scripts/
  run_suricata.sh            # pcap → suricata eve.json
  run_zeek.sh                # pcap → zeek NDJSON (네이티브 없으면 docker zeek 폴백)
  extract_log.sh <pcap>      # 위 둘을 한번에 → output/<name>/{suricata,zeek}
  build_evidence.py <name>   # 로그 → output/<name>/evidence.json (tier1 번들)
  make_policy.py <name>      # reports/<name>.json → reports/<name>.rules (Suricata)
  score.py [reports]         # reports/*.json 을 answers/truth 와 비교 채점
llm/
  config.py                  # .env 로더 + REPORT/VERDICT 스키마 + 프롬프트 로드
  tools.py                   # Tools 클래스: evidence.json 을 읽어주는 코드 API
  run.py                     # 분석 단계: triage → forensic → 코드 안전가드 → reports/<name>.json
  render_report.py           # reports/<name>.json + .rules → reports/<name>.md (한글)
  prompts/
    triage.md                # triage 시스템 프롬프트
    forensic.md              # forensic 시스템 프롬프트
  test.py                    # tool-calling 스모크(레거시, 분석 경로 미사용)
kaggle/
  run_pipeline.ipynb         # Kaggle 러너 (전 단계 자동)
answers/truth/<case>.json    # 채점용 정답(수작업)
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
- `alerts` (Suricata 시그니처, severity, count, src/dst) · `external` (`ips`/`domains`/`sni`/**`http`**)
- `files` (해시·mime, 서빙 uid 조인) · `lateral_movement` (dst 역할별 dcerpc_ops/smb_writes)
- `anomalies` (무시그니처 행동: 비콘 지터, 업로드 비율, no-DNS 직결, odd-port, 역할이탈, DNS 엔트로피)

핵심: **http 요청 URI를 evidence로 올린다** — path traversal/웹공격은 시그니처가 없어도 URI에 드러나므로.

### 3) 분석 — `llm/run.py <name>` (아래 "run.py 상세" 참조)
`reports/<name>.json` 저장. 채점(`score.py`)·룰생성(`make_policy`)·보고서(`render_report`)의 공통 입력.

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

### 채점 — `scripts/score.py reports`
`reports/*.json` 을 `answers/truth/<case>.json` 과 비교. 지표: `verdict`, `victimR`(피해자 recall),
`iocR`/`domR`/`hashR`(IOC/도메인/해시 recall), `infra!`(인프라를 피해자로 오인), `grd`(그라운딩=환각 탐지),
`fp`(정상을 악성으로). **모델 비교(bakeoff)의 심판** — 모델 바꿔 돌리고 AGG 비교.

---

## `llm/run.py` 상세 — 분석 단계 (네가 처음 짠 것, 많이 바뀜)

`main()` 흐름: `triage → (사건이면) forensic → 코드 가드 4개 → 저장`.

| 함수 | 역할 | 소유 |
|---|---|---|
| **`triage(tools)`** | 1차 판정 `no_incident`/`suspicious`/`confirmed`. tier1 근거 주입 + `format=VERDICT_SCHEMA` 단일 chat. `no_incident`면 분석 안 감(무혐의를 사건으로 프레이밍하는 것 차단). | LLM |
| **`forensic(tools)`** | 본 분석. `format=REPORT_SCHEMA` 단일 chat → victims/iocs/timeline/patient_zero/anomaly_analysis/attacks 등 구조화 JSON. | LLM |
| **`attach_identity(analysis, tools)`** | victims 의 `mac/hostname/username` 을 evidence 조인으로 **코드가 확정**(LLM 베끼기 손상·누락 교정). `clean_ip`가 구분자 손상 IP(`10.6_15.187`) 를 숫자 재조립+호스트 검증으로 복구, `patient_zero`도 IP만 정규화. | 코드 |
| **`attach_hashes(analysis, tools)`** | `iocs.hashes` 를 evidence `files[]` 에서 코드가 채움(LLM 해시 블라인드니스 방지). windowsupdate 등 **업데이트 인프라가 서빙한 x-dosexec 은 오탐이라 제외**(`_excluded_benign_hashes`). | 코드 |
| **`ground_iocs(analysis, tools)`** | iocs 의 IP/도메인을 **evidence 관측집합과 대조** — 없으면 오염/환각으로 제거. `host_of`가 LLM 장식(`"1.2.3.4 (Beacon)"`)·URL·JSON누출에서 알맹이만 추출, 버킷 오배치 도메인 salvage, **내부 자산(호스트 IP·AD 존)·TLD·공용접미사 기각**. 제거분 `_rejected_iocs`. | 코드 |
| **`annotate_attacks(analysis, tools)`** | `attacks[]` 의 `actor_scope`/`target_scope`(내부/외부)를 호스트 인벤토리로 채움 → 차단 반응 분기(내부 actor=호스트격리 / 외부=IP차단 / 표적=차단안함). 표적(피격자)을 iocs 에서 제거(자폭 방지). `_removed_attack_targets`. | 코드 |
| `create_rules(tools)` | **미사용 스텁**(비활성). 차단룰은 `make_policy.py`가 코드로 함. | — |

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
| `get_alerts()` | Suricata 알럿 전량(시그니처/severity/count/src/dst) |
| `get_external()` | **알럿에 엮인** 외부 ip/도메인 + sni (배경 CDN/텔레메트리 노이즈 제거) |
| `get_http()` | 웹 요청 전량(method/url/uri/status/UA) — **무필터**(웹공격은 alert 없어도 URI에 있음) |
| `get_files()` | 멀웨어 후보 파일(실행/압축/스크립트)은 전문, 나머지는 mime별 요약 |
| `get_lateral_movement()` | 내부↔내부: dst 역할별 dcerpc_ops/smb_shares/smb_writes (정찰 vs 실행 구분 재료) |
| `get_anomalies()` | 무시그니처 행동 측정치(비콘/업로드비율/no-dns/odd-port/역할이탈/DNS엔트로피) |

**(B) 코드 전용 헬퍼 — 가드가 쓰는 것들 (LLM 미노출)**
| 메서드 | 용도 |
|---|---|
| `malware_candidate_hashes()` | 멀웨어 해시를 서빙호스트로 악성/정상 분리 (attach_hashes) |
| `serving_host_for_hash(sha)` | files→http uid 조인으로 그 해시를 서빙한 호스트 |
| `observed_iocs()` | 그라운딩 기준집합 = evidence의 **"외부 관측" IP/도메인/해시**. 내부 자산(호스트IP·AD존·내부전용 해석 이름)은 **원천 제외** (ground_iocs 가 이걸로 대조) |

`get_host_info`/`get_alerts_by_severity`/`search_external` 은 단건 조회용(레거시 tool 스모크, 분석 경로 미사용).

---

## `llm/config.py` — 설정 단일 소스
리포 루트 `.env` 를 읽어 노출: `MODEL`, `NUM_CTX`, `OPTS`(temperature/seed/num_ctx), `VERDICT_SCHEMA`,
`REPORT_SCHEMA`(둘 다 ollama `format` 강제용), `SYSTEM_PROMPT_TRIAGE/FORENSIC`(=`prompts/*.md`).
**프롬프트는 코드 아니라 `.md` 파일**, **설정은 `.env` 한 줄** — 코드 안 건드리고 튜닝.

---

## 실행

### 로컬
```bash
./setup.sh                                       # 최초 1회
./scripts/extract_log.sh pcaps/<파일>.pcap        # → output/<name>/{suricata,zeek}
python3 scripts/build_evidence.py <name>          # → output/<name>/evidence.json
cd llm && python3 run.py <name>                   # → reports/<name>.json   (ollama 필요)
cd .. && python3 scripts/make_policy.py <name> --validate   # → reports/<name>.rules
cd llm && python3 render_report.py <name>         # → reports/<name>.md
python3 scripts/score.py reports                  # 정답 대비 채점(answers/truth 있을 때)
```

### Kaggle
`kaggle/run_pipeline.ipynb` — Settings에서 **Internet ON + GPU**, pcap 데이터셋 Add Input, Run All.
재실행은 "★ 재실행 시작점" 셀부터(코드/`.env` 최신화 후 pcap마다 전 단계 자동).

---

## 모델 교체 (bakeoff)

`.env` 의 `MODEL=` 한 줄만 바꾸면 됨(config.py 단일 소스). 요건은 **tool 지원이 아니라 `format`(구조화 출력) 지원** —
llama.cpp 그래머라 대부분 모델 가능.

**하드웨어 현실 (2×T4 = 16GB×2, NVLink 없음):**
- **한 카드(16GB)에 통째로 드는 모델**이 스윗스팟 — split 안 해서 빠름.
- 27B(≈18GB)는 두 카드에 쪼개져 PCIe 오버헤드 → **pcap당 5분+** (느리지만 배치 포렌식엔 감내 가능).
- 후보: `gemma3:27b`, `mistral-small3.2:24b`, `phi4:14b`(빠름). 70B·qwen/deepseek 제외.
- 안 뜨면(OOM) `.env` `NUM_CTX` 낮추기.

**비교법**: 같은 pcap 세트로 각 모델 → `score.py` AGG 나란히. 코드가 팩트를 받쳐서 **판단 품질만 순수 비교**됨.

---

## 알려진 한계 / TODO
- **모델 천장**: 로컬 26~27B는 run마다 결과가 달라지고(비결정), 덜 뽑거나(도메인 누락) 과하게 넣음(정당 서비스). 코드 가드로 팩트는 지키지만 recall/판단은 모델 몫.
- **CDN 과차단 (미해결·우선)**: 악성 도메인이 Cloudflare 뒤에 있으면 IP가 공유 엣지(104.16/13, 104.21/16, 172.67/16)로 풀림 → LLM이 그 IP를 c2에 넣으면 룰이 **Cloudflare 전체를 차단**. gemma·qwen 둘 다(심지어 Cloudflare인 걸 알면서도) 밟음 → **모델로 못 고침, make_policy에 CDN 가드 필요.**
- **서술이 분석 에러를 증폭**: render_report는 분석을 충실히 한글로 풀 뿐, 분석이 틀리면 자신만만하게 틀린 보고서가 됨(예: 근거 없는 측면이동 서술). → adversarial 검증층(red-team) 미구현.
- **암호화/외부인텔 한계**: TLS 내부 payload·DoH·정상 사이트 악용(github/maven 호스팅) 등은 pcap+시그니처만으론 불가 — 천장이지 버그 아님.
- **검증셋 좁음**: MTA류 교육용 pcap 위주. 실제 기업망(대용량·멀티호스트·시끄러움) 미검증.
