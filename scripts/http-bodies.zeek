# HTTP 요청/응답 본문 + 요청 헤더를 http.log 에 인라인으로 남긴다.
#
# 왜: Zeek 기본 http.log 은 request_body_len(길이 숫자)만 남기고 본문 내용은 버린다.
#     → URL(URI)엔 안 실리는 공격이 통째로 사라진다:
#       - POST body 기반 SQLi/XSS/webshell 업로드/command injection
#       - 헤더 기반 공격 (Log4Shell ${jndi:...}, User-Agent/Referer/X-Forwarded-For SQLi)
#       - 응답 본문에 드러나는 공격 '성공'의 증거 (SQL 에러/쿼리 반사/유출 데이터)
#     이 스크립트가 req_body/resp_body/req_headers 컬럼을 추가해 build_evidence 가
#     읽어 LLM 에 전달한다. 판단은 LLM 몫 — 여기선 팩트만 실어 나른다.
#
# 캡: 페이로드 판별엔 앞부분이면 충분하고, 컨텍스트 예산도 지켜야 하므로 앞부분만 남긴다
#     (build_evidence 가 evidence.json 단계에서 한 번 더 짧게 캡한다).

redef record HTTP::Info += {
    req_body:    string &optional &log;
    resp_body:   string &optional &log;
    req_headers: string &optional &log;   # Host/User-Agent 제외 (별도 컬럼)
};

const MAX_BODY = 2048 &redef;
const MAX_HDRS = 1024 &redef;

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {
    if ( ! c?$http )
        return;
    if ( is_orig )
        {
        if ( ! c$http?$req_body || |c$http$req_body| < MAX_BODY )
            c$http$req_body = c$http?$req_body ? c$http$req_body + data : data;
        }
    else
        {
        if ( ! c$http?$resp_body || |c$http$resp_body| < MAX_BODY )
            c$http$resp_body = c$http?$resp_body ? c$http$resp_body + data : data;
        }
    }

event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( ! is_orig || ! c?$http )
        return;
    if ( name == "HOST" || name == "USER-AGENT" )   # 이미 http.log 에 별도 컬럼
        return;
    if ( c$http?$req_headers && |c$http$req_headers| >= MAX_HDRS )
        return;
    local h = name + ": " + value;
    c$http$req_headers = c$http?$req_headers ? c$http$req_headers + " | " + h : h;
    }
