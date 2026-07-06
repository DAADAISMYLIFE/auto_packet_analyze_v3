"""
Defines the tools the local LLM (sLLM) can call.
"""

import os, json, statistics
from collections import defaultdict

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

    # =========================== Tier 2: 원본 로그 드릴다운 ===========================
    #  LLM 이 tool 로 호출하지 않는다. run.py 가 evidence(tier1)에서 파라미터를 뽑아
    #  코드가 직접 조회한다 — 대상 선정·타입매핑·uid 조인 전부 코드 몫(LLM 판단 0).
    #  카테고리 키 존재 = 조회함(빈 값이어도), per-entity [] = 조회했으나 없음.

    MAX_TIER2_ENTITIES = 20  # 케이스당 상한 (실측상 보통 <20, 방어적 캡)
    INFRA_ROLES = ("domain_controller", "dns_server", "dhcp", "gateway")
    # 업데이트/텔레메트리 인프라 — 여기서 서빙된 실행파일은 멀웨어 아님(오탐 방지)
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

    def _service_index(self):
        """ip → conn.log 에서 관측된 service 집합 (http/ssl 무차별 호출 방지)."""
        if not hasattr(self, "_svc"):
            idx = defaultdict(set)
            for r in self._zeek("conn.log"):
                svc = r.get("service")
                if svc:
                    for ip in (r.get("id.orig_h"), r.get("id.resp_h")):
                        if ip:
                            idx[ip].add(svc)
            self._svc = idx
        return self._svc

    def serving_host_for_hash(self, sha256):
        """files.log 에서 sha256 매칭 → 그 flow 의 uid 로 http.log 조인 → 서빙 host/uri.
        community_id 가 아니라 files.log 원본의 uid 를 쓴다(조인 정확)."""
        for f in self._zeek("files.log"):
            if f.get("sha256") == sha256:
                h = self._http_by_uid().get(f.get("uid"), {}) if f.get("source") == "HTTP" else {}
                return {"sha256": sha256, "serving_ip": f.get("id.resp_h"),
                        "serving_host": h.get("host"), "uri": h.get("uri"),
                        "user_agent": h.get("user_agent"), "mime": f.get("mime_type")}
        return {"sha256": sha256, "serving_ip": None, "serving_host": None,
                "uri": None, "user_agent": None, "mime": None}

    def malware_candidate_hashes(self):
        """malware-candidate 해시를 서빙 호스트로 악성/정상(업데이트 인프라) 분리.
        코드가 소유 → LLM 해시 블라인드 + 윈도우업데이트 오탐 둘 다 차단.
        반환: {"malware":[sha...], "benign_excluded":[{sha256,serving_host}...]}"""
        mal, benign = [], []
        for f in self.get_files().get("malware_candidates", []):
            sha, mime = f.get("sha256"), (f.get("mime") or "")
            if not sha or "ms-pol" in mime:      # ms-pol = DC 배포 GPO, 멀웨어 아님
                continue
            prov = self.serving_host_for_hash(sha)
            host = (prov.get("serving_host") or "").lower()
            if host and any(b in host for b in self.BENIGN_SERVING):
                benign.append({"sha256": sha, "serving_host": prov["serving_host"]})
            else:
                mal.append(sha)
        return {"malware": sorted(set(mal)), "benign_excluded": benign}

    # ---- 원본 로그 드릴다운 (타입별) ----

    def raw_http(self, ip=None, uid=None, limit=15):
        rows = [r for r in self._zeek("http.log")
                if (uid and r.get("uid") == uid)
                or (ip and ip in (r.get("id.orig_h"), r.get("id.resp_h")))]
        # (host,uri,user_agent) 조합별 그룹핑 — head(N) 로 자르면 UA 로테이션 신호 손실
        groups = defaultdict(list)
        for r in rows:
            groups[(r.get("host"), r.get("uri"), r.get("user_agent"))].append(r)
        out = []
        for (host, uri, ua), g in sorted(groups.items(), key=lambda kv: -len(kv[1]))[:limit]:
            ts = sorted(x.get("ts") for x in g if x.get("ts") is not None)
            out.append({"host": host, "uri": uri, "user_agent": ua, "count": len(g),
                        "first_ts": ts[0] if ts else None,
                        "methods": sorted({x.get("method") for x in g if x.get("method")}),
                        "status": sorted({x.get("status_code") for x in g if x.get("status_code")}),
                        "resp_bytes": sorted({x.get("response_body_len") for x in g
                                              if x.get("response_body_len")})[:3]})
        return out

    def raw_conn(self, ip, limit=15):
        rows = [r for r in self._zeek("conn.log") if ip in (r.get("id.orig_h"), r.get("id.resp_h"))]
        groups = defaultdict(list)
        for r in rows:
            groups[(r.get("id.orig_h"), r.get("id.resp_h"), r.get("id.resp_p"), r.get("service"))].append(r)
        out = []
        for (src, dst, port, svc), g in sorted(groups.items(), key=lambda kv: -len(kv[1]))[:limit]:
            ts = sorted(x["ts"] for x in g if x.get("ts") is not None)
            ivals = [b - a for a, b in zip(ts, ts[1:])]
            out.append({"src": src, "dst": dst, "port": port, "service": svc, "flows": len(g),
                        "bytes_out": sum(x.get("orig_bytes") or 0 for x in g),
                        "bytes_in": sum(x.get("resp_bytes") or 0 for x in g),
                        "beacon_interval_s": round(statistics.mean(ivals), 1) if len(ivals) >= 4 else None,
                        "beacon_jitter_s": round(statistics.pstdev(ivals), 1) if len(ivals) >= 4 else None})
        return out

    def raw_dns(self, query, limit=5):
        rows = [r for r in self._zeek("dns.log") if r.get("query") == query]
        return [{"ts": r.get("ts"), "query": r.get("query"), "answers": r.get("answers"),
                 "TTLs": r.get("TTLs"), "rcode_name": r.get("rcode_name")} for r in rows[:limit]]

    def raw_ssl(self, ip, limit=10):
        # 이 zeek 빌드는 ja3 미출력 → server_name/version/cipher/established 만 반환
        seen, out = set(), []
        for r in self._zeek("ssl.log"):
            if ip not in (r.get("id.orig_h"), r.get("id.resp_h")):
                continue
            key = (r.get("server_name"), r.get("id.resp_h"))
            if key in seen:
                continue
            seen.add(key)
            out.append({"ts": r.get("ts"), "sni": r.get("server_name"), "version": r.get("version"),
                        "cipher": r.get("cipher"), "established": r.get("established")})
            if len(out) >= limit:
                break
        return out

    def raw_smtp(self, src_ip, limit=10):
        rows = [r for r in self._zeek("smtp.log") if r.get("id.orig_h") == src_ip]
        return [{"ts": r.get("ts"), "mailfrom": r.get("mailfrom"), "rcptto": r.get("rcptto"),
                 "subject": r.get("subject")} for r in rows[:limit]]

    def raw_smb(self, src, dst, limit=15):
        # 쓰기 액션만 = 실제 측면이동 실행 신호 (읽기/열기는 정상)
        rows = [r for r in self._zeek("smb_files.log")
                if r.get("id.orig_h") == src and r.get("id.resp_h") == dst
                and "WRITE" in (r.get("action") or "").upper()]
        return [{"ts": r.get("ts"), "action": r.get("action"), "path": r.get("path"),
                 "name": r.get("name"), "size": r.get("size")} for r in rows[:limit]]

    def raw_kerberos(self, ip, limit=15):
        rows = [r for r in self._zeek("kerberos.log") if ip in (r.get("id.orig_h"), r.get("id.resp_h"))]
        return [{"ts": r.get("ts"), "client": r.get("client"), "service": r.get("service"),
                 "request_type": r.get("request_type"), "success": r.get("success"),
                 "error_msg": r.get("error_msg")} for r in rows[:limit]]

    def build_tier2(self):
        """evidence(tier1)에서 코드가 파라미터를 추출 → 원본 로그를 타입별로 드릴다운.
        LLM 판단 0(목록순회 + 타입매핑). 트리거 안 된 카테고리는 키 자체를 안 만든다."""
        ev = self.evidence
        internal = {h.get("ip") for h in ev.get("hosts", [])}
        infra = {h.get("ip") for h in ev.get("hosts", []) if h.get("role") in self.INFRA_ROLES}
        alerts = ev.get("alerts", [])
        anomalies = ev.get("anomalies", {})
        N = self.MAX_TIER2_ENTITIES

        ext_ips = sorted({ip for a in alerts
                          for ip in (a.get("src_ips") or []) + (a.get("dst_ips") or [])
                          if ip and ip not in internal})[:N]
        # 내부(피해자 후보) — UA 로테이션은 피해자 자신의 http 전체를 봐야 나옴(외부 IP 조회론 안 잡힘)
        victim_ips = sorted({ip for a in alerts for ip in (a.get("src_ips") or []) if ip in internal}
                            | {rd.get("src") for rd in anomalies.get("role_deviation", [])
                               if rd.get("src") in internal})[:N]
        alert_domains = sorted({d.get("query") for d in self.get_external().get("domains", [])
                                if d.get("query")})[:N]
        # SMTP 트리거는 알럿 텍스트 매칭이 아니라 anomalies 구조화 필드로(신종도 잡힘)
        has_smtp = any((rd.get("service") == "smtp") or (rd.get("port") in (25, 465, 587))
                       for rd in anomalies.get("role_deviation", []))
        mal_sha = [f.get("sha256") for f in self.get_files().get("malware_candidates", [])
                   if f.get("sha256")][:N]
        # 측면이동: 내부→내부(비인프라) 쌍만 (→DC 는 정상 AD 라 제외)
        lm = ev.get("lateral_movement", {})
        pairs = []
        for e in lm.get("ad_authentication", []) + lm.get("workstation_to_workstation", []):
            s, d = e.get("src"), e.get("dst")
            if s in internal and d in internal and d not in infra:
                pairs.append((s, d))
        for pr in lm.get("smb", {}).get("internal_pairs", []):
            if len(pr) == 2 and pr[0] in internal and pr[1] in internal and pr[1] not in infra:
                pairs.append((pr[0], pr[1]))
        pairs = list(dict.fromkeys(pairs))[:N]

        t2 = {}
        conn_ips = list(dict.fromkeys(ext_ips + victim_ips))
        if conn_ips:
            t2["conn"] = {ip: self.raw_conn(ip) for ip in conn_ips}
        svc = self._service_index()
        http_ips = list(dict.fromkeys(victim_ips + [ip for ip in ext_ips if "http" in svc.get(ip, ())]))
        if http_ips:
            t2["http"] = {ip: self.raw_http(ip=ip) for ip in http_ips}
        ssl_ips = [ip for ip in ext_ips if "ssl" in svc.get(ip, ())]
        if ssl_ips:
            t2["ssl"] = {ip: self.raw_ssl(ip) for ip in ssl_ips}
        if alert_domains:
            t2["dns"] = {d: self.raw_dns(d) for d in alert_domains}
        if has_smtp:
            t2["smtp"] = {ip: self.raw_smtp(ip) for ip in victim_ips}
        if mal_sha:
            t2["files"] = {sha: self.serving_host_for_hash(sha) for sha in mal_sha}
        if pairs:
            t2["smb"] = {f"{s}->{d}": self.raw_smb(s, d) for s, d in pairs}
            t2["kerberos"] = {s: self.raw_kerberos(s) for s, d in pairs}
        return t2
