import re
from parsers.base import BaseParser

class NmapParser(BaseParser):
    def parse(self, command: str, stdout: str, stderr: str = "") -> list:
        ports = []
        for line in stdout.split('\n'):
            m = re.search(r'^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?$', line, re.MULTILINE)
            if not m:
                m = re.search(r'(\d+)/(tcp|udp)\s+open\s+(\S+)', line)
            if m:
                ports.append({
                    "key": f"{m.group(1)}/{m.group(2)}",
                    "port": int(m.group(1)),
                    "proto": m.group(2),
                    "service": m.group(3),
                    "version": (m.group(4) or "").strip(),
                })
        return ports
