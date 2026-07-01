# auto_packet_analyze_v3

pcap을 넣으면 자동으로 네트워크 포렌식 분석을 수행하고, 사람은 마지막에 **보고서를 읽고 차단 정책 적용 여부만 선택**하는 파이프라인. 목표는 **인간 개입의 최소화**.

Suricata / Zeek 로 pcap에서 로그를 추출하고, 로컬 LLM(Ollama)이 그 로그를 근거로 피해자·공격자·공격 행위·타임라인을 분석하고 차단 패턴을 제안한다.

## 흐름
1. pcap 업로드
2. Suricata + Zeek 로그 추출
3. 정규화 및 압축
4. LLM 분석 (피해자/공격자 정보, 공격 판단, 타임라인, 차단 정책 생성)
5. LLM 보고서 + 적용 여부 질문
6. 사용자 선택 (근거는 LLM이 제공)

## 요구 사항
- Ubuntu (테스트: 22.04)
- Suricata, Zeek, Ollama — `setup.sh`가 설치

## 빠른 시작
```bash
# 1) 환경 구성 (suricata/zeek/ollama 설치 + 모델 pull)
./setup.sh

# 2) pcap에서 로그 추출 → output/<pcap이름>/{suricata,zeek}
./scripts/extract_log.sh pcaps/your-file.pcap

# 3) LLM tool-calling 확인
cd llm && python3 test.py
```

## 구조
```
setup.sh              # 설치 + 모델 pull + 동작 확인
scripts/
  run_suricata.sh     # pcap → Suricata eve.json
  run_zeek.sh         # pcap → Zeek NDJSON 로그
  extract_log.sh      # 위 둘을 한번에 실행
llm/
  tools.py            # LLM tool 함수 + 자동 스키마 등록소
  test.py             # tool-calling 동작 확인
```

## 상태
개발 중 (WIP).
