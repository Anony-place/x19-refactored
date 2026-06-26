"""Parsers package — converts raw tool output into structured observations."""

from parsers.base import BaseParser
from parsers.nmap import NmapParser
from parsers.httpx import HttpxParser
from parsers.gobuster import GobusterParser
from parsers.ffuf import FfufParser

__all__ = [
    "BaseParser",
    "NmapParser",
    "HttpxParser",
    "GobusterParser",
    "FfufParser",
]
