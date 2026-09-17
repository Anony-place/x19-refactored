import re
from parsers.base import BaseParser

class MasscanParser(BaseParser):
    def parse(self, command: str, stdout: str, stderr: str = "") -> list:
        ports = []
        for line in stdout.splitlines():
            # Discovered open port 80/tcp on 192.168.1.1
            m = re.search(r'open\s+port\s+(\d+)/(tcp|udp)', line, re.IGNORECASE)
            if m:
                ports.append({
                    "key": f"{m.group(1)}/{m.group(2).lower()}",
                    "port": int(m.group(1)),
                    "proto": m.group(2).lower(),
                    "service": "unknown",
                    "version": "",
                })
        return ports
