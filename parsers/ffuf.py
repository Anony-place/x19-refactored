import re
from parsers.base import BaseParser

class FfufParser(BaseParser):
    def parse(self, command: str, stdout: str, stderr: str = "") -> list:
        endpoints = []
        base_url = ""
        m_base = re.search(r'-u\s+(https?://[^\s]+)', command)
        if m_base:
            base_url = m_base.group(1)

        for line in stdout.splitlines():
            m = re.search(r'^([^\s]+)\s+\[Status:\s+(\d+)', line.strip(), re.I)
            if m and base_url:
                keyword = m.group(1)
                status = int(m.group(2))
                url = base_url.replace("FUZZ", keyword).replace("fuzz", keyword)
                import re as _re
                url = _re.sub(r'(?<!:)//+', '/', url)
                endpoints.append({
                    "url": url,
                    "status": status
                })
        return endpoints
