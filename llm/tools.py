"""
Defines the tools the local LLM (sLLM) can call.
"""

import os, json

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

        Returns every host found in the capture with its IP, MAC, hostname, and username.
        """
        
        # 1. hosts 필드 파싱
        hosts = self.evidence.get("hosts", [])

        # 2. ip, mac, hostname, username 정보 가져오기
        result = [
            {
                "ip": h.get("ip"),
                "mac": h.get("mac"),
                "hostname": h.get("hostname"),
                "username": h.get("username"),
                "role": h.get("role"),
                "scope": h.get("scope"),
                "ad_domain": h.get("ad_domain"),
            }
            for h in hosts
        ]

        # 3. return
        return result

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
