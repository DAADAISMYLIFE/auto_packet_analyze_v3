# 구조 상세

> README는 "무엇을, 왜"까지만. 이 문서는 모듈 단위로 "어떻게"를 적는다. 기준 커밋 59ed135 (2026-09-10).

## 0. 데이터 흐름

```
pcap ─extract_log.sh─▶ output/<case>/{suricata/eve.json, zeek/*.log}
       │
       ├─build_evidence.py──────────▶ output/<case>/evidence.json          (결정론, 판단 없음, 캡·편차·신호)
       │     └─ --noalert ──────────▶ output/<case>-noalert/evidence.json  (알럿만 0 — ablation 행)
       │
       ├─run.py --floor────────────▶ reports/floor/<case>.json             (LLM 0회 바닥: code_triage + 승격기 + 가드)
       │
       └─run.py ───────────────────▶ reports/<case>.json
             code_triage ─(알럿/해시 있음)─▶ suspicious 바닥 ┐
                         ─(조용한 캡처)──▶ LLM triage ───────┤─▶ forensic(LLM 1콜, JSON 스키마 강제, 캐시)
                                                              └─▶ apply_guards(PASSES) ─▶ upgrade_verdict ─▶ _llm_delta
                    │
                    ├─make_policy.py ─▶ reports/<case>.rules   (순수 코드; S1 drop + S2 content)
                    └─render_report.py ▶ reports/<case>.md     (코드가 표 주입 + LLM 서술 1콜 + [ o / x ])
       │
       └─score.py [--compare reports/floor reports] ─▶ recall/precision 표 (answers/truth/<case>.json)
```

Kaggle: `kaggle/run_pipeline.ipynb`(7셀, 항상 Run All) — ①설정 ②설치 ③서버·진단 ④파이프라인(Phase A 바닥 → Phase B LLM) ⑤채점·보고서 ⑥번들 ⑦캐시 데이터셋(선택).

## 1. 추출 — `scripts/extract_log.sh`, `run_suricata.sh`, `run_zeek.sh`

- Suricata: ET Open 룰, eve.json(alert 이벤트만 사용). community_id 로 Zeek conn 과 조인.
- Zeek: conn/dns/http/files/ssl/dce_rpc/smb/kerberos/… NDJSON. 로컬 스크립트 `hash-files.zeek`(sha256 강제), `http-bodies.zeek`(요청/응답 본문·헤더 캡처, MAX_BODY 2048 소프트 캡). 네이티브 없으면 docker 폴백(이 경로는 로컬 스크립트를 로드하지 않음 — 알려진 한계).

## 2. Evidence — `scripts/build_evidence.py` + `scripts/baseline.py`

**원칙**: 결정론. 판단(휴리스틱 결론)은 안 하고 **측정·정규화·랭크**만 한다. 같은 로그 → 같은 evidence(단, 엔트로피 top-5 정렬에 set 순회가 섞여 PYTHONHASHSEED 의존 — 리뷰 D-7).

주요 필드:
| 필드 | 내용 |
|---|---|
| `meta` | 캡처 창(epoch), duration_s, flow 수, hard/noise 카운트 |
| `hosts` | ip/mac/hostname/username/role(dhcp·kerberos·dns 조인)/ad_domain/활동창 |
| `alerts` | 시그니처별 집계 + **`threat_class`**(threat/rat/benign/unclassified — `baseline.threat_class()` 단일 소스) |
| `external.ips/domains/sni/http` | 외부 목적지. domains 에 srcs/answered/rcodes. http 는 URL/method/status/UA/body/헤더(캡 300, 신호 우선) |
| `files` | 해시·mime·서빙 uid. 멀웨어 후보 mime 은 전문 |
| `lateral_movement` | 내부↔내부 dcerpc/smb 프로파일(dst 역할별) |
| `anomalies` | 비콘(지터·S0비율·중앙값 규칙성·span), 업로드 비율, 무DNS 직결, odd-port, 역할이탈, DNS 엔트로피, brute_force |
| `signals` | RPC 기법 라벨(OP_MEANING), zeek weird, 프로토콜 요약, 존재 로그 |
| `deviations` | baseline 대비 편차 랭크(`top`, `host_deviations`, `baseline_suppressed`, `dns_search_suffix`, `ad_rpc`) — 캡 **전** 전량으로 계산 |
| `_truncation` | 캡 탈락 건수(tier 별·대표성 예약 유입) |

**캡 정책** `signal_priority_cap`: 인바운드 > 위협alert 연결 > 이상행동 목적지 > 의심TLD > 웹공격 패턴 > 시간순. 15% 대표성 예약(미대표 호스트 1행씩) 선공제 후 tier 최소 할당. (리뷰 D-3: noise tier 에도 최소 좌석이 가서 q2 inbound 64% 탈락 — 개선 대상.)

**baseline.py**: KNOWN_NORMAL 도메인/대역(soft 신호만 억제), hard/soft 신호 분리, `_search_suffixes`(부모 ≥3 서브 + NXDOMAIN + non-NX 없음 + answered 없음 + wpad/isatap/자기호스트명 마커 **필수**), DNS 터널 후보, AD/RPC 기본 정상.

**`--noalert`**: `eve = []` 로 알럿만 제거한 evidence 를 `output/<case>-noalert/` 에. `_ablation` 밑줄 키는 LLM 번들에 안 들어간다(테스트로 잠금).

## 3. LLM 뷰 — `llm/tools.py`

`Tools(case)` 는 evidence.json 을 읽어주는 코드 API. (이름은 tool-calling 시절 유산 — 분석 경로에서 tool 로 쓰이지 않는다.)

- **tier1 getter**: get_meta / get_hosts_info / get_alerts / get_external / get_http·`http_view(level)` / get_files / get_lateral_movement / get_anomalies / get_signals.
- **http_view 단계** (예산 초과 시에만): 0 전량 → 1 신호없는 행 지문 → 2 접기(템플릿+건수) → 3 목적지별 건수(host·sample_url 보존) → 4 신호 행도 페이로드 기준 접기(표본 3 + 개수). 신호 행 = 인바운드·위협alert·편차·이상행동·의심TLD·웹패턴. 접은 건 `_view` 로 모델에 알림.
- **코드 전용**: `observed_iocs()`(그라운딩 기준집합 — 외부 IP·도메인·SNI·http Host·해시; 내부 자산 제외), `malware_candidate_hashes()`(BENIGN_SERVING 호스트 제외), `serving_host_for_hash()`(files→http uid 조인; ablation 케이스는 원본 Zeek 로그 사용).
- 분류기: `is_threat_alert`, `is_malware_comm_alert`, `SUSP_TLD`, `WEB_ATTACK_PAT`.

## 4. 분석 — `llm/run.py`

**컨텍스트 예산** `_tier1(tools, mode)`: `estimate_tokens`(숫자 1자=1토큰, 구두점 1토큰, 나머지 3.5자/토큰) 로 예산(NUM_CTX×0.6 forensic / ×0.25 triage) 안에 들 때까지 http 뷰를 강등. 최대 강등 후에도 넘치면 **호출 전** `LLMError`.

**호출** `_chat(stage, **kw)`: ollama chat 래퍼. prefill/decode 토큰·속도·사고 크기 출력. 서버 에러는 LLMError 로(main 이 보고서에 `pipeline_status` 기록).

**verdict 경로**
```
code_triage: threat/rat alert 또는 멀웨어 후보 해시 → suspicious(LLM triage 생략)
             아니면 → LLM triage(VERDICT_SCHEMA: no_incident/suspicious/confirmed)
no_incident → 종료(분석 없음)      ※ 이때 승격기도 안 돈다 (ablation 이 드러낸 한계)
그 외 → forensic(REPORT_SCHEMA) → apply_guards → upgrade_verdict(compromised≥1 ∧ (c2 ∨ hashes) → confirmed)
```

**forensic 캐시**: `output/<case>/forensic_raw.json`, 키 = sha256(system+tier1 메시지 | MODEL | THINK). 모드 auto(동일 sha 면 재생) / `--fresh` / `--replay`(LLM 절대 호출 안 함). (리뷰 C-6: OPTS·스키마가 키에 없음, 파싱 실패도 캐시됨.)

**CaseContext**: internal_ips, ad_domains, external_ips(아웃바운드 dst), c2_flagged(멀웨어 통신 alert 의 외부 IP), attack_targets(LLM attacks 에서 C2 계열 technique 제외한 target), search_suffixes, observed. 가드 실행 **전**에 한 번 계산(리뷰 C: LLM 오기 하나가 승격기 4개를 막는 단일 실패점).

**PASSES** (순서가 규칙 — 정리 → 승격):
| 가드 | 역할 |
|---|---|
| `attach_identity` | victims 의 ip 정규화(옥텟 재조립·장식 제거), mac/hostname/username/role 을 evidence 조인으로 확정 |
| `demote_infra_victims` | 정상 AD 인증을 받는 DC/DNS 를 compromised→infrastructure(격리 자폭 방지) |
| `attach_hashes` | iocs.hashes 를 files 에서 코드가 채움, 업데이트 인프라 서빙분 제외(`_excluded_benign_hashes`) |
| `ground_iocs` | 관측집합 대조 — 미관측·내부 자산·TLD·검색 접미사 기각(`_rejected_iocs`), 버킷 오배치 salvage |
| `annotate_attacks` | actor/target scope 확정, 피격자(표적)를 iocs 에서 제거(`_removed_attack_targets`). C2 계열 technique 의 target 은 보호(`_c2_kept_despite_target_label`) |
| `attach_iocs_from_alerts` | threat/rat alert 의 외부 관측 IP → c2 |
| `attach_iocs_from_dns` | 의심 TLD 도메인 중 실제 접속한 해석 IP + 그 IP → c2/domains |
| `attach_inbound_threat_ips` | 인바운드 위협 alert 의 외부 출발지 → c2 (`_iocs_added_inbound`) |
| `attach_dead_beacons` | conns≥100 ∧ span≥1h ∧ 무응답(bytes_in=0 or S0≥0.9) ∧ 중앙값 규칙성≥60% ∧ 캡처≥2h ∧ 글로벌 유니캐스트 → c2 (`_iocs_added_dead_beacon`) |

**floor_report**: 같은 PASSES 경로를 analysis 빈 객체에 적용(victims 는 비움 — 설계). **_llm_delta**: full 모드에서 같은 함수로 바닥을 선계산해 verdict/iocs/domains/victims 델타를 보고서에 기재.

## 5. 정책 — `scripts/make_policy.py`

- S1 drop: `iocs.c2/delivery/exfil` ∪ external actor → `drop ip $HOME_NET any -> X any` (리뷰 B-1: 인바운드 공격자에겐 방향이 틀림); domains → `drop dns`(dns.query) + `drop tls`(tls.sni); internal actor → `drop ip HOST any -> any any`(완전 격리). Cloudflare/Fastly 대역·인프라(DC/DNS) 제외.
- S2 content(alert): 악성 flow 의 특징적 URI 경로(길이≥6, 호스트별 LCS, 랜덤 제외), 도구 UA, POST 키, 명령주입 pcre. (리뷰 B-2/B-3: pcre `;` 미이스케이프, `/click`류 오탐.)
- sid 1000000+/1100000+ 케이스마다 0부터(리뷰 B-5). `--validate` → `suricata -T`.

## 6. 보고서 — `llm/render_report.py`

코드가 표(피해 호스트/IOC/타임라인/룰)를 주입하고 LLM 이 개요·시나리오·권고 3필드만 서술(format 강제 1콜, THINK_NARRATIVE). 섹션: 1 개요 · 2 판정+근거 · 3 피해 호스트 · 4 IOC · 5 타임라인 · 6 시나리오 · 7 룰 · 8 권고 + **[ o / x ]** · 9 커버리지 한계(=assessment). (리뷰 B-7/8: attacks·patient_zero·`_iocs_added_*` 근거 미출력, 에러 경로.)

## 7. 채점 — `scripts/score.py`

행 = `reports/<label>.json`, truth = `answers/truth/<key>.json`(8자리 날짜 또는 stem; `-noalert` 접미사는 떼고 원본 truth). 열: verdict / victimR·P / infra!(DC 를 compromised 로 부름) / iocR·P / domR·P(suffix) / hashR / fp(truth benign 을 악성으로) / pz. `--compare A B` 로 두 디렉터리를 나란히. (리뷰 A-5/7: suffix 양방향, AGG 분모 미표시.)

## 8. 설정 — `.env` → `llm/config.py`

MODEL / NUM_CTX / THINK(true·false·low·medium·high) / THINK_NARRATIVE / TEMPERATURE·TOP_P·TOP_K·SEED / NUM_PREDICT. 스키마(VERDICT/REPORT)와 프롬프트(`llm/prompts/*.md`) 로드. 인라인 주석은 별도 줄에만.

## 9. 테스트 — `llm/test_guards.py`(36) · `llm/test_views.py`(13)

GPU·ollama 없이 1초. FakeTools 로 evidence dict 주입. 잠그는 계약: 가드 순서·그라운딩·C2 보호·접미사(마커 필수, SERVFAIL 비접미사)·죽은비콘 승격+반례 4종·캡 대표성·뷰 무손실·예산 거부·precision 의미론·THINK 파서·floor·캐시·ablation(알럿만 제거, 표식 미노출)·채점 라벨. (리뷰: 버그를 정답으로 고정한 테스트 3건 있음.)

## 10. 노트북 — `kaggle/run_pipeline.ipynb`

| 셀 | 하는 일 | 재실행 |
|---|---|---|
| ① 설정 | clone/pull, ollama 서버 env(flash attention, KV q8_0, keep_alive, sched_spread), .env 에서 MODEL/THINK | ~2s |
| ② 설치 | setup.sh(조용·멱등; 캐시 데이터셋 있으면 모델 복원) | ~5s |
| ③ 서버·진단 | ollama 기동, **config.OPTS 동일 옵션**으로 format 강제 프로브, 100% GPU 확인, 테스트 2종 게이트 | ~20s |
| ④ 파이프라인 | Phase A: 케이스마다 추출(로그 있으면 스킵)→evidence(+`--noalert`)→floor→바닥 채점. Phase B: MODE all/sentinel, run.py(캐시 auto)→make_policy→render, ablation 행은 채점만, checkpoint push(GH_PAT 있을 때) | evidence 동일하면 초 단위 |
| ⑤ 채점·보고서 | `score.py --compare reports/floor reports` + MD 표시 | — |
| ⑥ 번들 | evidence+forensic_raw+reports zip(로컬 `--replay`용) | — |
| ⑦ 캐시 데이터셋 | (선택) ~/.ollama → Kaggle Dataset(KAGGLE 시크릿 필요, 없으면 조용히 통과) | — |
