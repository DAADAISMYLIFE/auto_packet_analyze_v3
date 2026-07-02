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

    def get_files(self):
        """Collect transferred files.

        Returns exchanged files (sha256, md5, mime, bytes, source, first_ts) — malware candidates.
        """

        # 1. files 필드 파싱
        files = self.evidence.get("files", [])

        # 2. 정보 가져오기
        result = [
            {
                "sha256": f.get("sha256"),
                "md5": f.get("md5"),
                "mime": f.get("mime"),
                "bytes": f.get("bytes"),
                "sources": f.get("sources"),
                "first_ts": f.get("first_ts"),
            }
            for f in files
        ]

        # 3. return
        return result

    def get_lateral_movement(self):
        """Collect lateral-movement signals.

        Returns the internal-spread summary (smb / dcerpc / ldap / kerberos).
        """

        # 1. lateral_movement 필드 파싱 후 return
        return self.evidence.get("lateral_movement", {})
