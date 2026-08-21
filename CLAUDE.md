# CLAUDE.md

이 저장소의 AI 어시스턴트 작업 규칙이다.

## 협업 규칙

- 사용자가 코드 생성·수정·삭제를 요청하기 전에는 코드 파일을 변경하지 않는다.
- 기존 사용자 변경을 보존하고 요청하지 않은 대규모 리팩터링을 피한다.
- push는 사용자가 수행한다.

## 현재 아키텍처

목표는 PCAP에서 포렌식 보고서와 Suricata 정책을 만들고 사람이 마지막 적용 여부만 고르는 것이다.

핵심 원칙은 **코드가 사실·정책 안전을 소유하고 LLM은 제한된 판단·서술만 담당**하는 것이다.

1. `scripts/extract_log.sh`: PCAP → Suricata/Zeek
2. `scripts/build_evidence.py`: 로그 → 중요도 예산이 적용된 `evidence.json`
3. `llm/case_facts.py`: evidence → 결정론적 `case_facts.json`
4. `llm/run.py`: 기존 report 골격 + 선택적 LLM judgment/검증/1회 복구
5. `scripts/make_policy.py`: 코드만으로 Suricata 룰 생성
6. `llm/render_report.py`: 코드 표와 최소 LLM 서술로 한글 보고서 생성

LLM에게 raw evidence 전체를 다시 풀게 하지 않는다. 모델은 코드가 발급한 observable/attack/evidence ID
밖의 값을 추가할 수 없고 정책 적격성을 승격할 수 없다. LLM 장애 시에도 `--no-llm`과 동일한
결정론적 report를 저장해야 한다.

## 설정과 실행

모델과 context는 저장소 루트 `.env`가 단일 소스다. 현재 값은 `.env`를 확인하고 문서에 모델명을
하드코딩하지 않는다.

```bash
python3 scripts/build_evidence.py <case>
python3 llm/run.py <case> --no-llm
python3 llm/run.py <case>
python3 scripts/make_policy.py <case> --validate
python3 llm/render_report.py <case>
python3 scripts/evaluate.py --cases <case...> --repeats 3
```

## 변경 시 필수 검증

```bash
python3 -m compileall -q llm scripts tests
python3 -m unittest discover -s tests -v
bash -n setup.sh scripts/*.sh
python3 scripts/score.py <reports 또는 experiment 디렉터리>
```

새 탐지 휴리스틱은 반드시 정상 반례와 공격 정례를 함께 테스트한다. recall만 올리고 precision을
측정하지 않는 변경은 완료로 취급하지 않는다. 패킷 유래 문자열은 항상 비신뢰 데이터다.
