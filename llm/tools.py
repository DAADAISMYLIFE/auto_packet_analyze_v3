"""
Defines the tools the local LLM (sLLM) can call.
"""

import ipaddress, os, json, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

"""
=============================== Tier 1 facts ===============================
Facts that MUST be extractable from the evidence file.
========================================================================== 
"""

# ── 위협 alert 판정: 단일 소스는 evidence 의 threat_class(build_evidence 가 baseline.threat_class 로 스탬프).
#    필드가 없는 '구 evidence.json' 에서만 정규식 폴백. (숫자 severity 는 못 믿는다 — ET CHAT Skype 가 sev1.)
_THREAT_SIG = re.compile(
    r"\b(MALWARE|TROJAN|CNC|COINMINER|EXPLOIT|ATTACK_RESPONSE|WEB_SERVER|"
    r"WEB_SPECIFIC_APPS|CURRENT_EVENTS|SCAN|PHISHING|WORM|ROOTKIT|DOS|"
    r"SHELLCODE|MOBILE_MALWARE|REMOTE_ACCESS)\b", re.I)


def is_threat_alert(a):
    tc = a.get("threat_class")
    if tc is not None:
        return tc in ("threat", "rat")
    return bool(_THREAT_SIG.search(a.get("signature") or ""))


# 멀웨어-통신 계열 카테고리 — 이 alert 가 가리키는 '외부' IP 는 공격당한 피해자가 아니라
# 악성 인프라(C2/RAT/봇넷)다. WEB_SERVER/EXPLOIT/SCAN 등 '서버를 공격' 카테고리는 제외 —
# 그 dst 는 진짜 피격자일 수 있다. (annotate_attacks 표적 제거의 예외 판단용, 결정론)
_MALWARE_COMM_SIG = re.compile(
    r"\b(MALWARE|TROJAN|CNC|BOTNET|COINMINER|CURRENT_EVENTS|PHISHING|"
    r"MOBILE_MALWARE|WORM|ROOTKIT|REMOTE_ACCESS)\b", re.I)


def is_malware_comm_alert(a):
    return bool(_MALWARE_COMM_SIG.search(a.get("signature") or ""))


class Tools:
    # ── LLM 뷰 강등 단계 (http). evidence.json 은 무손실 — 줄이는 건 '보여주는 것'뿐 ──
    #   0 전량(= get_http, 예산 안이면 오늘과 동일)  1 신호없는 행 응답/헤더 지문
    #   2 신호없는 행 접기(템플릿 그룹+건수)          3 신호없는 행 목적지별 건수
    #   4 신호 행도 접기(페이로드 표본 유지) — triage 급
    #   '신호 행'(인바운드·위협alert·편차·이상행동·의심TLD·웹공격패턴)은 0~3 에서 항상 전량.
    HTTP_VIEW_LEVELS = 5
    SUSP_TLD = re.compile(r"\.(?:su|cc|cyou|xyz|top|tk|gq|ml|cf|ga)$", re.I)
    # 일반 웹공격 패턴 — 보조 신호일 뿐. 목록 밖의 '처음 보는' 공격은 인바운드 규칙이 받친다.
    WEB_ATTACK_PAT = re.compile(
        r"(?:\.\./|%2e%2e|union(?:%20|\+|\s)+select|\(\)\s*\{\s*:\s*;|[?&](?:cmd|exec)=|"
        r"filename=[^\r\n]{0,80}\.(?:php|jsp|aspx)|/etc/passwd|%00)", re.I)

    def __init__(self, filename):
        # evidence 파일 로드
        self.base = os.path.join(ROOT, "output", filename)
        with open(os.path.join(self.base, "evidence.json"), encoding="utf-8") as f:
            self.evidence = json.load(f)
            
        # tool 등록 
        self.TOOLS = [self.get_host_info, self.get_alerts_by_severity, self.search_external]
        self.AVAILABLE = {fn.__name__: fn for fn in self.TOOLS}


    def get_hosts_info(self):
        """Collect all hosts.

        Returns every host found in the capture with its IP, MAC, hostname, username,
        and activity window (first_ts/last_ts, epoch seconds) — the window is the
        patient-zero ordering signal.
        """

        # 1. hosts 필드 파싱
        hosts = self.evidence.get("hosts", [])

        # 2. ip, mac, hostname, username + 활동 시간창
        result = [
            {
                "ip": h.get("ip"),
                "mac": h.get("mac"),
                "hostname": h.get("hostname"),
                "username": h.get("username"),
                "role": h.get("role"),
                "scope": h.get("scope"),
                "ad_domain": h.get("ad_domain"),
                "first_ts": h.get("first_ts"),
                "last_ts": h.get("last_ts"),
            }
            for h in hosts
        ]

        # 3. return
        return result

    def get_meta(self):
        """Capture metadata: pcap name, capture window (epoch), duration_s, flow counts.

        triage 프롬프트가 '짧은 캡처면 비콘/DNS 휴리스틱 불신'을 지시하므로
        duration 이 모델에 반드시 도달해야 한다.
        """
        return self.evidence.get("meta", {})

    def get_host_info(self, ip: str):
        """Get one host's full detail.

        Returns all fields for the host matching the given IP (None if not found).

        Args:
            ip: the IP address to look up.
        """
        
        for h in self.evidence.get("hosts", []):
            if h.get("ip") == ip:
                return h

        return None

    def get_alerts(self):
        """Collect all Suricata alerts.

        Returns every alert (signature, category, severity) found by Suricata.
        """

        # 1. alerts 필드 파싱
        alerts = self.evidence.get("alerts", [])

        # 2. 정보 가져오기
        result = [
            {
                "signature": a.get("signature"),
                "category": a.get("category"),
                "severity": a.get("severity"),
                "threat_class": a.get("threat_class"),   # 코드의 위협/정황 분류 → LLM 에 노출
                "count": a.get("count"),
                "first_ts": a.get("first_ts"),
                "src_ips": a.get("src_ips"),
                "dst_ips": a.get("dst_ips"),
            }
            for a in alerts
        ]

        # 3. return
        return result

    def get_alerts_by_severity(self, severity: int):
        """Collect Suricata alerts of a given severity.

        Returns all alerts whose severity matches (1 = highest, range 1-3).

        Args:
            severity: alert severity level (1-3).
        """

        return [a for a in self.evidence.get("alerts", []) if a.get("severity") == severity]

    def get_external(self):
        """Collect the alert-linked external contacts (the C2 / malware IOCs).

        Returns only external IPs/domains that a Suricata alert references (an IP seen in
        an alert, or a domain named in an alert signature or resolving to a flagged IP),
        plus SNI and a count of the un-flagged background. This drops benign CDN/telemetry
        noise. To reach ALL external contacts (e.g. a benign-looking precursor domain),
        use search_external.
        """
        e = self.evidence
        alert_ips = {ip for a in e.get("alerts", [])
                     for ip in (a.get("src_ips", []) + a.get("dst_ips", []))}
        # signatures often defang domains ("hillcoweb .com") → strip spaces before matching
        sigs = "".join(a.get("signature", "") for a in e.get("alerts", [])).lower().replace(" ", "")
        ext = e.get("external", {})
        ips = [x for x in ext.get("ips", []) if x.get("ip") in alert_ips]
        doms = [d for d in ext.get("domains", [])
                if d.get("query", "").lower() in sigs
                or (set(d.get("answers") or []) & alert_ips)]
        return {"ips": ips, "domains": doms, "sni": ext.get("sni", [])[:20],
                "background_ips": len(ext.get("ips", [])) - len(ips),
                "background_domains": len(ext.get("domains", [])) - len(doms)}

    def get_http(self):
        """웹 요청 전량(method/url/uri/status/UA/src + req_body/resp_body/req_headers) — 무필터.

        get_external 은 alert-linked 만 통과시키지만 http 는 그러면 안 된다:
        traversal/injection 은 시그니처가 없어(=alert 없음) alert 로 거르면 사라진다.
        alert 유무와 무관하게 전량 넘겨 LLM 이 URI·body·헤더를 직접 판단하게 한다.
        (req_body/resp_body/req_headers 는 http-bodies.zeek 가 채우면 존재 — POST/헤더 공격 가시화.
         토큰은 build_evidence 가 dedup+cap 으로 이미 관리.)
        """
        return self.evidence.get("external", {}).get("http", [])

    def search_external(self, keyword: str) -> dict:
        """Search ALL external contacts (not just alert-linked) by substring.

        Use when you need an external IP/domain/SNI that get_external dropped as
        background — e.g. a benign-looking precursor domain (patient-zero).

        Args:
            keyword: substring to match against external IPs, domains, and SNI.
        """
        k = keyword.lower()
        ext = self.evidence.get("external", {})
        ips = [x for x in ext.get("ips", []) if k in x.get("ip", "").lower()]
        doms = [d for d in ext.get("domains", []) if k in d.get("query", "").lower()]
        sni = [s for s in ext.get("sni", []) if k in s.get("sni", "").lower()]
        return {"ips": ips[:30], "domains": doms[:30], "sni": sni[:30]}

    # 멀웨어 후보로 취급할 mime (부분일치) — 이 외의 파일은 mime별 집계로만 요약
    #   주의: "zip" 같은 짧은 토큰은 x-gzip(HTTP 압축 응답 노이즈)까지 잡으므로 "/zip", "x-zip" 사용
    INTERESTING_MIME = ("x-dosexec", "x-executable", "x-dosdriver", "/zip", "x-zip", "rar",
                        "x-7z", "msdownload", "ms-pol", "x-msi", "java-archive",
                        "vbs", "powershell", "x-sh", "hta")

    def get_files(self):
        """Collect transferred files.

        Returns malware-candidate files (executables/archives/scripts) in full, and
        summarizes the rest per mime (count/total_bytes) to keep the context small.
        """
        files = self.evidence.get("files", [])
        interesting, background = [], {}
        for f in files:
            mime = f.get("mime") or "unknown"
            if any(k in mime for k in self.INTERESTING_MIME):
                interesting.append({
                    "sha256": f.get("sha256"),
                    "mime": mime,
                    "bytes": f.get("bytes"),
                    "first_ts": f.get("first_ts"),
                    "sources": f.get("sources"),
                    "community_id": (f.get("community_ids") or [None])[0],
                })
            else:  # 노이즈(윈도우 업데이트 CAB, OCSP, text 등)는 건수/용량만
                b = background.setdefault(mime, {"count": 0, "total_bytes": 0})
                b["count"] += 1
                b["total_bytes"] += f.get("bytes") or 0
        return {"malware_candidates": interesting,
                "background_by_mime": background,
                "note": "background files are summarized; drill down if needed"}

    def get_lateral_movement(self):
        """Collect lateral-movement signals.

        Returns the internal-spread summary (smb / dcerpc / ldap / kerberos).
        """

        # 1. lateral_movement 필드 파싱 후 return
        return self.evidence.get("lateral_movement", {})


    def get_anomalies(self):
        """Collect signature-less behavioral measurements (beacon jitter, upload
        ratio, no-DNS direct connects, odd ports, role deviation, DNS entropy, and
        brute_force = repetition/rate/auth-failure counts for volumetric attacks
        (credential flooding / auth-repetition) that signatures routinely miss).
        """

        return self.evidence.get("anomalies", {})

    def get_signals(self):
        """Protocol-agnostic signal layer (no per-log function, no tool-calling):
        - techniques: RPC ops LABELED via a lookup table (execution = WMI/DCOM/remote
          service create/schtasks, cred_theft = directory replication pull, cred_attack
          = repeated netlogon auth, recon = AD enumeration) — surfaced REGARDLESS of
          smb_writes or lateral_movement bucket.
        - zeek_weird: Zeek's own protocol-anomaly detections (weird.log).
        - protocol_summary: every other log (rdp/ssh/ftp/smtp/… and future logs)
          auto-summarized as (src,dst,port,count).
        - logs_present: which logs existed (what was / was not observed).
        This is the catch-all the per-protocol views miss (e.g. WMI lateral movement).
        """
        return self.evidence.get("signals", {})

    # ===================== 해시 provenance (원본 로그 조인, 코드 전용) =====================
    #  attach_hashes 오탐 방지 전용 최소 리더 — LLM 에 노출하는 tier2 는 만들지 않는다.
    #  업데이트/텔레메트리 인프라가 서빙한 실행파일은 멀웨어가 아님(MS Defender 업데이트 등).
    BENIGN_SERVING = ("windowsupdate.com", "download.microsoft.com", "delivery.mp.microsoft.com",
                      "update.microsoft.com", "msftconnecttest.com", "digicert.com",
                      # q2 카빙 검증(2026-09-02): 서명된 NVIDIA 드라이버·AOL CDN 광고 SWF 가
                      # iocs.hashes 로 승격되던 오탐 — 정품 배포 인프라 서빙분은 멀웨어 아님
                      "nvidia.com", "aolcdn.com")

    def _zeek(self, name):
        """zeek NDJSON 로그를 1회 로드 후 캐시. 파일 없으면 []."""
        if not hasattr(self, "_zc"):
            self._zc = {}
        if name not in self._zc:
            path = os.path.join(self.base, "zeek", name)
            if not os.path.exists(path) and self.base.endswith("-noalert"):
                # ablation 케이스(build_evidence --noalert)는 evidence.json 만 가진다 —
                # 원본 Zeek 로그(files/http 조인용)는 원본 케이스 디렉터리에서 읽는다.
                path = os.path.join(self.base[:-len("-noalert")], "zeek", name)
            rows = []
            if os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    for line in f:
                        try:
                            rows.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
            self._zc[name] = rows
        return self._zc[name]

    def _http_by_uid(self):
        """uid → 그 flow 의 첫 http 요청 (files→http serving-host 조인용)."""
        if not hasattr(self, "_huid"):
            idx = {}
            for h in self._zeek("http.log"):
                idx.setdefault(h.get("uid"), h)
            self._huid = idx
        return self._huid

    def serving_host_for_hash(self, sha256):
        """files.log 에서 sha256 매칭 → 그 flow 의 uid 로 http.log 조인 → 서빙 host/uri.
        community_id 가 아니라 files.log 원본의 uid 를 쓴다(조인 정확)."""
        for f in self._zeek("files.log"):
            if f.get("sha256") == sha256:
                h = self._http_by_uid().get(f.get("uid"), {}) if f.get("source") == "HTTP" else {}
                return {"serving_ip": f.get("id.resp_h"), "serving_host": h.get("host"),
                        "uri": h.get("uri")}
        return {"serving_ip": None, "serving_host": None, "uri": None}

    def malware_candidate_hashes(self):
        """malware-candidate 해시를 서빙 호스트로 악성/정상(업데이트 인프라) 분리.
        코드가 소유 → LLM 해시 블라인드 + 윈도우업데이트 오탐 둘 다 차단.
        반환: {"malware":[sha...], "benign_excluded":[{sha256,serving_host}...]}"""
        mal, benign = [], []
        for f in self.get_files().get("malware_candidates", []):
            sha, mime = f.get("sha256"), (f.get("mime") or "")
            if not sha or "ms-pol" in mime:      # ms-pol = DC 배포 GPO, 멀웨어 아님
                continue
            host = (self.serving_host_for_hash(sha).get("serving_host") or "").lower()
            if host and any(b in host for b in self.BENIGN_SERVING):
                benign.append({"sha256": sha, "serving_host": host})
            else:
                mal.append(sha)
        return {"malware": sorted(set(mal)), "benign_excluded": benign}

    def observed_iocs(self):
        """grounding 기준집합: evidence 에서 '실제 관측된 외부' IP/도메인/해시.

        전체 트리 regex walk 가 아니라 구조화 필드만 읽는다 — 내부호스트·유저명이
        기준집합에 섞이면 오염이 통과하므로(초기 score.py 버그) 반드시 구조화 필드로.
          external.ips[].ip + domains[].answers  →  관측 IP
          external.domains[].query + sni[].sni    →  관측 도메인
          files[].sha256 / .md5                    →  관측 해시

        내부 자산은 기준집합에서 원천 제외 (차단정책 자폭 방지 — DC 를 c2 로 내도 통과 못 함):
          - answers 의 사설/내부 IP        (AD DNS 가 DC IP 를 답하는 경로)
          - AD 존 소속 이름                (kerberos ad_domain + '_msdcs.<존>' SRV 로 식별)
          - 내부로만 풀리는 이름            (답이 전부 사설/내부 = 내부 존)
          - answers 의 CNAME 문자열        (IP 집합에 도메인이 섞이는 오염)
        """
        e = self.evidence
        ext = e.get("external", {}) or {}
        internal = {str(h.get("ip")) for h in e.get("hosts", []) if h.get("ip")}

        ad_zones = {str(h["ad_domain"]).lower()
                    for h in e.get("hosts", []) if h.get("ad_domain")}
        for d in ext.get("domains", []) or []:
            q = str(d.get("query") or "").lower()
            if "._msdcs." in q:
                ad_zones.add(q.split("._msdcs.", 1)[1])

        def priv(a):
            try:
                return ipaddress.ip_address(str(a)).is_private
            except ValueError:
                return None                      # IP 아님 (CNAME 문자열 등)

        def in_ad_zone(n):
            return any(n == z or n.endswith("." + z) for z in ad_zones)

        ips, doms, hashes = set(), set(), set()
        for x in ext.get("ips", []) or []:
            if x.get("ip"):
                ips.add(str(x["ip"]).lower())
        for d in ext.get("domains", []) or []:
            q, ans = str(d.get("query") or "").lower(), (d.get("answers") or [])
            ext_ans = [str(a).lower() for a in ans
                       if priv(a) is False and str(a) not in internal]
            if q and not in_ad_zone(q) and (ext_ans or not ans):
                doms.add(q)
            ips.update(ext_ans)
        for s in ext.get("sni", []) or []:
            sni = str(s.get("sni") or "").lower()
            if sni and not in_ad_zone(sni):
                doms.add(sni)
        # http Host 헤더 도메인 — DNS 질의 없이 '직결 + Host 헤더'로만 존재하는 C2/TDS 가 있다
        #   (q2 실측: searchl.org / 2hood.eu — dns.log 질의 0건, 그라운딩이 환각으로 오인 기각).
        #   sni 와 같은 기준으로 관측집합에 포함. bare-IP 호스트·AD 존은 제외.
        for h in ext.get("http", []) or []:
            host = str(h.get("url") or "").split("/", 1)[0].lower().split(":", 1)[0]
            if host and "." in host and not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host) \
                    and not in_ad_zone(host):
                doms.add(host)
        for f in e.get("files", []) or []:
            for k in ("sha256", "md5"):
                if f.get(k):
                    hashes.add(str(f[k]).lower())
        return {"ips": ips, "domains": doms, "hashes": hashes}

    # ===================== LLM 뷰: http 단계적 강등 (코드 전용, 결정론) =====================
    def _http_signal_sets(self):
        """행이 '신호 행'인지 판정할 집합들 — 전부 evidence 의 코드 산출물에서 나온다."""
        e = self.evidence
        internal = {str(h.get("ip")) for h in e.get("hosts", []) if h.get("ip")}
        threat_ips = {str(ip) for a in e.get("alerts", []) if is_threat_alert(a)
                      for ip in (a.get("src_ips") or []) + (a.get("dst_ips") or [])}
        dev = e.get("deviations") or {}
        dev_ips = {str(d.get("dest")).lower() for d in (dev.get("top") or []) if d.get("kind") == "ip"}
        dev_doms = {str(d.get("dest")).lower() for d in (dev.get("top") or []) if d.get("kind") == "domain"}
        an = e.get("anomalies") or {}
        anomaly_dsts = {str(x.get("dst")) for k in ("beacons", "exfil_candidates", "no_dns_direct", "odd_ports")
                        for x in (an.get(k) or []) if x.get("dst")}
        return internal, threat_ips, dev_ips, dev_doms, anomaly_dsts

    def _is_signal_http(self, h, S):
        internal, threat_ips, dev_ips, dev_doms, anomaly_dsts = S
        dst = str(h.get("dst_ip") or "")
        host = str(h.get("url") or "").split("/", 1)[0].lower()
        if dst in internal:                                   # 인바운드 = 공격면 (패턴 무관)
            return True
        if dst in threat_ips or dst in anomaly_dsts or dst in dev_ips:
            return True
        if any(host == d or host.endswith("." + d) for d in dev_doms):
            return True
        if self.SUSP_TLD.search(host):
            return True
        blob = " ".join(str(h.get(k) or "") for k in ("url", "req_body", "req_headers"))
        return bool(self.WEB_ATTACK_PAT.search(blob))

    @staticmethod
    def _url_template(url):
        """랜덤 경로/ID 를 접기 위한 템플릿: 숫자열→N, 8자+ 영숫자 토큰→*  (클릭사기·CDN 해시 경로 그룹화)."""
        u = str(url or "")
        u = re.sub(r"[A-Za-z0-9+_-]{8,}", "*", u)
        return re.sub(r"\d+", "N", u)

    @staticmethod
    def _fp(v, n):
        if v is None or v == "None" or v == "":
            return None
        v = str(v)
        return v if len(v) <= n else v[:n] + "…"

    def _fold(self, rows, fp_len):
        """같은 (src, dst, method, status, url템플릿) 행을 그룹 하나로. 건수 보존 + 표본 1개."""
        groups = {}
        for h in rows:
            key = (tuple(h.get("src_ips") or []), h.get("dst_ip"), h.get("method"),
                   str(h.get("status")), self._url_template(h.get("url")))
            g = groups.get(key)
            if g is None:
                g = groups[key] = {
                    "url_template": key[4], "sample_url": h.get("url"), "method": h.get("method"),
                    "dst_ip": h.get("dst_ip"), "src_ips": h.get("src_ips"), "status": h.get("status"),
                    "user_agent": self._fp(h.get("user_agent"), 60),
                    "requests": 0, "rows_folded": 0, "first_ts": h.get("first_ts"),
                    "req_body": self._fp(h.get("req_body"), fp_len),
                    "req_headers": self._fp(h.get("req_headers"), fp_len),
                    "resp_body": self._fp(h.get("resp_body"), fp_len // 2 or 1),
                }
            g["requests"] += int(h.get("count") or 1)
            g["rows_folded"] += 1
            ts = h.get("first_ts")
            if ts is not None and (g["first_ts"] is None or ts < g["first_ts"]):
                g["first_ts"] = ts
            for k in ("req_body", "req_headers", "resp_body"):     # 표본은 '내용 있는 것' 우선
                if not g[k] and h.get(k) not in (None, "None", ""):
                    g[k] = self._fp(h[k], fp_len if k != "resp_body" else fp_len // 2 or 1)
        return sorted(groups.values(), key=lambda g: (g["first_ts"] is None, g["first_ts"]))

    def _fold_by_payload(self, rows, fp_len):
        """신호 행 접기 — '무엇을 보냈나'(헤더/바디 템플릿) 기준. 스캐너/익스플로잇 스프레이는 같은
        페이로드로 수백 경로를 두드리므로 경로별로 접으면 그룹이 폭증한다. 경로는 표본 3개 + 개수."""
        groups = {}
        for h in rows:
            key = (tuple(h.get("src_ips") or []), h.get("dst_ip"), h.get("method"),
                   self._url_template(self._fp(h.get("req_headers"), fp_len)),
                   self._url_template(self._fp(h.get("req_body"), fp_len)))
            g = groups.get(key)
            if g is None:
                g = groups[key] = {
                    "method": h.get("method"), "dst_ip": h.get("dst_ip"), "src_ips": h.get("src_ips"),
                    "sample_urls": [], "distinct_urls": 0, "statuses": set(),
                    "user_agent": self._fp(h.get("user_agent"), 60),
                    "requests": 0, "rows_folded": 0, "first_ts": h.get("first_ts"),
                    "req_headers": self._fp(h.get("req_headers"), fp_len),
                    "req_body": self._fp(h.get("req_body"), fp_len),
                    "resp_body": self._fp(h.get("resp_body"), fp_len // 2 or 1),
                }
            g["requests"] += int(h.get("count") or 1)
            g["rows_folded"] += 1
            g["distinct_urls"] += 1
            if len(g["sample_urls"]) < 3:
                g["sample_urls"].append(h.get("url"))
            g["statuses"].add(str(h.get("status")))
            ts = h.get("first_ts")
            if ts is not None and (g["first_ts"] is None or ts < g["first_ts"]):
                g["first_ts"] = ts
            if not g["resp_body"] and h.get("resp_body") not in (None, "None", ""):
                g["resp_body"] = self._fp(h["resp_body"], fp_len // 2 or 1)
        out = []
        for g in groups.values():
            g["statuses"] = sorted(g["statuses"]); out.append(g)
        return sorted(out, key=lambda g: (g["first_ts"] is None, g["first_ts"]))

    @staticmethod
    def _summarize_by_dst(rows):
        by = {}
        for h in rows:
            # host + sample_url 보존 — 접힌 행도 '누구와 무엇' 은 보이게 (Wajam 실증:
            # dst_ip 건수만 남기면 webenhancer 애드웨어가 LLM 시야에서 소멸)
            d = by.setdefault(str(h.get("dst_ip")), {"dst_ip": h.get("dst_ip"), "host": None,
                                                    "sample_url": None, "rows": 0, "requests": 0,
                                                    "methods": set(), "statuses": set(), "first_ts": None})
            d["rows"] += 1; d["requests"] += int(h.get("count") or 1)
            d["methods"].add(str(h.get("method"))); d["statuses"].add(str(h.get("status")))
            url = str(h.get("url") or "")
            if d["host"] is None and url:
                d["host"] = url.split("/", 1)[0]
                d["sample_url"] = url if len(url) <= 80 else url[:80] + "…"
            ts = h.get("first_ts")
            if ts is not None and (d["first_ts"] is None or ts < d["first_ts"]):
                d["first_ts"] = ts
        out = []
        for d in by.values():
            d["methods"] = sorted(d["methods"]); d["statuses"] = sorted(d["statuses"])
            out.append(d)
        return sorted(out, key=lambda d: -d["requests"])

    def http_view(self, level):
        """level 0 = get_http() 그대로(리스트). 1+ = {_view, signal_rows, other_*} — 접은 건 반드시 알린다."""
        rows = self.get_http()
        if level <= 0:
            return rows
        S = self._http_signal_sets()
        sig = [h for h in rows if self._is_signal_http(h, S)]
        other = [h for h in rows if not self._is_signal_http(h, S)]
        view = {"level": level, "total_rows": len(rows), "signal_rows": len(sig), "other_rows": len(other),
                "signal_rule": "inbound-to-internal | threat-alert dst | deviation dest | anomaly dst | susp-TLD | web-attack pattern"}
        out = {"_view": view}
        if level == 1:
            view["other_shown_as"] = "fingerprint(resp_body/req_headers 80자)"
            out["signal_rows"] = sig
            out["other_rows"] = [dict(h, resp_body=self._fp(h.get("resp_body"), 80),
                                      req_headers=self._fp(h.get("req_headers"), 80)) for h in other]
        elif level == 2:
            folded = self._fold(other, 80)
            view["other_shown_as"] = f"folded into {len(folded)} groups (url template + count)"
            out["signal_rows"] = sig
            out["other_groups"] = folded
        elif level == 3:
            summ = self._summarize_by_dst(other)
            view["other_shown_as"] = f"per-destination counts ({len(summ)} dsts)"
            out["signal_rows"] = sig
            out["other_summary"] = summ
        else:
            folded = self._fold_by_payload(sig, 160)
            summ = self._summarize_by_dst(other)
            view["signal_shown_as"] = f"folded by payload into {len(folded)} groups (sample_urls 3 + distinct_urls), payload 160자"
            view["other_shown_as"] = f"per-destination counts ({len(summ)} dsts)"
            out["signal_groups"] = folded
            out["other_summary"] = summ
        return out


# ====================== LLM 전송용 무손실 구조 압축 ======================
# 프롬프트(tier1_evidence) 직렬화 직전에만 쓴다. evidence.json/Tools.evidence 는
# 키-값 그대로 — ground_iocs/attach_identity/score.py 는 이 함수를 모른다.
# (Tools 의 tool 이 아니라 코드용 헬퍼 — TOOLS 에 등록하지 않는다.)

TABLE_MIN = 4   # 이 건수 이상의 균일 dict 리스트만 표로 (미만은 키-값 앵커 유지가 SLM 오독 방지에 안전)

def compact_evidence(v):
    """균일한 dict 리스트를 {columns, rows} 표로 바꿔 키 반복만 걷어낸다 (무손실).

    값(URL/IP/ts/중첩 리스트)은 한 글자도 안 바꾼다 — http 섹션 기준 ~45% 절감.
    전부 null 인 열은 rows 에서 빼되 empty_columns 로 명시
    ('봤는데 전부 없음' 신호 보존 — 침묵 삭제 금지 원칙).
    """
    if isinstance(v, list) and len(v) >= TABLE_MIN and all(isinstance(x, dict) for x in v):
        cols = []                               # 등장 순서 보존한 키 합집합
        for e in v:
            for k in e:
                if k not in cols:
                    cols.append(k)
        empty = [c for c in cols if all(e.get(c) is None for e in v)]
        live = [c for c in cols if c not in empty]
        t = {"_format": "table", "columns": live,
             "rows": [[e.get(c) for c in live] for e in v]}
        if empty:
            t["empty_columns"] = empty
        return t
    if isinstance(v, dict):
        return {k: compact_evidence(x) for k, x in v.items()}
    if isinstance(v, list):
        return [compact_evidence(x) for x in v]
    return v
