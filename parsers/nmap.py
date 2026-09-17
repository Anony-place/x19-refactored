import re
from parsers.base import BaseParser

class NmapParser(BaseParser):
    def parse(self, command: str, stdout: str, stderr: str = "") -> list:
        ports = []
        for line in stdout.split('\n'):
            line_str = line.strip()
            # 1. Standard Nmap: 80/tcp open http Apache 2.4.41
            m = re.search(r'^(\d+)/(tcp|udp)\s+open\s*(\S+)?(?:\s+(.+))?$', line_str, re.IGNORECASE)
            if not m:
                m = re.search(r'(\d+)/(tcp|udp)\s+open\s*(\S+)?', line_str, re.IGNORECASE)
            # 2. Masscan: Discovered open port 80/tcp on 192.168.1.1
            if not m:
                m_mass = re.search(r'open\s+port\s+(\d+)/(tcp|udp)', line_str, re.IGNORECASE)
                if m_mass:
                    ports.append({
                        "key": f"{m_mass.group(1)}/{m_mass.group(2).lower()}",
                        "port": int(m_mass.group(1)),
                        "proto": m_mass.group(2).lower(),
                        "service": "unknown",
                        "version": "",
                    })
                    continue
            # 3. Rustscan: Open 127.0.0.1:80 or 80/open/tcp
            if not m:
                m_rust = re.search(r'Open\s+[\d\.]+:(\d+)', line_str) or re.search(r'(\d+)/open/(tcp|udp)', line_str, re.IGNORECASE)
                if m_rust:
                    port_num = int(m_rust.group(1))
                    proto = m_rust.group(2).lower() if m_rust.lastindex and m_rust.lastindex >= 2 else "tcp"
                    ports.append({
                        "key": f"{port_num}/{proto}",
                        "port": port_num,
                        "proto": proto,
                        "service": "unknown",
                        "version": "",
                    })
                    continue
            if m:
                ports.append({
                    "key": f"{m.group(1)}/{m.group(2).lower()}",
                    "port": int(m.group(1)),
                    "proto": m.group(2).lower(),
                    "service": (m.group(3) or "unknown").strip(),
                    "version": (m.group(4) or "").strip() if m.lastindex and m.lastindex >= 4 else "",
                })
        return ports
