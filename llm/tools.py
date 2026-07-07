"""
Defines the tools the local LLM (sLLM) can call.
"""

import ipaddress, os, json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

"""
=============================== Tier 1 facts ===============================
Facts that MUST be extractable from the evidence file.
========================================================================== 
"""

class Tools:
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
        """웹 요청 전량(method/url/uri/status/UA/src) — 무필터.

        get_external 은 alert-linked 만 통과시키지만 http 는 그러면 안 된다:
        traversal/injection 은 시그니처가 없어(=alert 없음) alert 로 거르면 사라진다.
        alert 유무와 무관하게 전량 넘겨 LLM 이 URI 를 직접 판단하게 한다.
        (토큰은 build_evidence 가 dedup+cap 으로 이미 관리.)
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
        ratio, no-DNS direct connects, odd ports, role deviation, DNS entropy).
        """

        return self.evidence.get("anomalies", {})

    # ===================== 해시 provenance (원본 로그 조인, 코드 전용) =====================
    #  attach_hashes 오탐 방지 전용 최소 리더 — LLM 에 노출하는 tier2 는 만들지 않는다.
    #  업데이트/텔레메트리 인프라가 서빙한 실행파일은 멀웨어가 아님(MS Defender 업데이트 등).
    BENIGN_SERVING = ("windowsupdate.com", "download.microsoft.com", "delivery.mp.microsoft.com",
                      "update.microsoft.com", "msftconnecttest.com", "digicert.com")

    def _zeek(self, name):
        """zeek NDJSON 로그를 1회 로드 후 캐시. 파일 없으면 []."""
        if not hasattr(self, "_zc"):
            self._zc = {}
        if name not in self._zc:
            path = os.path.join(self.base, "zeek", name)
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
        for f in e.get("files", []) or []:
            for k in ("sha256", "md5"):
                if f.get(k):
                    hashes.add(str(f[k]).lower())
        return {"ips": ips, "domains": doms, "hashes": hashes}
