"""
sLLM이 사용할 도구를 정의
"""

import os, json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

"""
=============================== Tier 1 정보 =============================== 
evidence 파일을 통해 반드시 찾아낼 수 있는정보
=========================================================================== 
"""

class Tools:
    def __init__(self, filename):
        # evidence 파일 로드
        self.base = os.path.join(ROOT, "output", filename)
        with open(os.path.join(self.base, "evidence.json"), encoding="utf-8") as f:
            self.evidence = json.load(f)
            
        # tool 등록 
        self.TOOLS = [self.get_hosts_info, self.get_host_info]
        self.AVAILABLE = {fn.__name__: fn for fn in self.TOOLS}


    def get_hosts_info(self):
        """모든 호스트 정보를 수집
        패킷에서 발견된 모든 호스트의 IP, MAC, hostname, username 정보를 수집
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
        """호스트 상세 정보를 수집
        호스트의 모든 정보 수집

        args : ip - 조회할 ip
        """
        
        for h in self.evidence.get("hosts", []):
            if h.get("ip") == ip:
                return h

        return None
