import re
from parsers.base import BaseParser

class HttpxParser(BaseParser):
    def parse(self, command: str, stdout: str, stderr: str = "") -> list:
        endpoints = []
        if '[200]' in stdout or '[301]' in stdout or '[302]' in stdout or '[' in stdout:
            for m in re.finditer(r'(https?://[^\s\[]+)\s*\[(\d{3})\]', stdout):
                endpoints.append({
                    "url": m.group(1).rstrip('/'),
                    "status": int(m.group(2))
                })
            # Try to grab other URLs without status codes but containing '['
            for l in re.findall(r'(https?://[^\s]+)\s+\[', stdout):
                if not any(e["url"] == l.rstrip('/') for e in endpoints):
                    endpoints.append({
                        "url": l.rstrip('/'),
                        "status": 0
                    })
        return endpoints
