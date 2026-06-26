import re
from parsers.base import BaseParser

class GobusterParser(BaseParser):
    def parse(self, command: str, stdout: str, stderr: str = "") -> list:
        endpoints = []
        base_url = ""
        # Extract base url
        m_base = re.search(r'-u\s+(https?://[^\s]+)', command)
        if not m_base:
            m_base = re.search(r'--url\s+(https?://[^\s]+)', command)
        if m_base:
            base_url = m_base.group(1).rstrip('/')

        for line in stdout.splitlines():
            m = re.search(r'^(/[^\s]+)\s+\(Status:\s+(\d+)\)', line.strip(), re.I)
            if m and base_url:
                endpoints.append({
                    "url": f"{base_url}{m.group(1)}",
                    "status": int(m.group(2))
                })
        return endpoints
