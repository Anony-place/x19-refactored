"""Decision parsing extracted from agent.py.

The X19._parse_decision method converts raw LLM text into structured decision
dicts. This module holds the pure parsing logic so planners and other modules
can interpret model decisions without importing the monolith.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional


def parse_decision(raw: str) -> Optional[Dict[str, Any]]:
    """Parse raw LLM text into a decision dictionary.

    Tries JSON block first, then longcat_tool_call blocks, then prose fallback.
    Returns None if no decision could be extracted.
    """
    if not raw:
        return None

    # Robust JSON extraction: scan each '{' with a real decoder. This handles
    # nested objects/arrays and braces inside strings correctly, unlike the old
    # non-greedy regex which truncated at the first '}' and broke whenever a
    # nested object (plan / finding / _mission_task) followed "completed".
    d = _extract_json_object(raw)
    if d is not None:
        return _normalize_decision(d)

    # Fallback: legacy regex for the simple flat-decision case.
    m = re.search(r'\{.*?"completed".*?\}', raw, re.DOTALL)
    if m:
        for attempt in (m.group(0), re.sub(r',\s*([}\]])', r'\1', m.group(0))):
            try:
                d = json.loads(attempt)
            except json.JSONDecodeError:
                continue
            if isinstance(d, dict):
                return _normalize_decision(d)

    # Longcat tool call format
    longcat_cmds = _extract_longcat_commands(raw)
    if longcat_cmds:
        return _normalize_decision({
            "completed": False,
            "next_command": longcat_cmds[0],
            "reasoning": "tool_call",
        })

    # Prose fallback
    prose = _extract_prose_command(raw)
    if prose:
        return _normalize_decision({
            "completed": False,
            "next_command": prose,
            "reasoning": "extracted from prose (model did not follow JSON format)",
        })

    return None


def _extract_json_object(raw: str) -> Optional[Dict[str, Any]]:
    """Return the first JSON object in `raw` that contains a "completed" key.

    Uses json.JSONDecoder.raw_decode at each '{' so nested objects, arrays,
    escaped quotes, and braces inside strings are all handled correctly.
    Returns None if no such object exists.
    """
    decoder = json.JSONDecoder()
    idx = raw.find("{")
    while idx != -1:
        try:
            obj, end = decoder.raw_decode(raw, idx)
        except json.JSONDecodeError:
            obj = None
            end = idx + 1
        if isinstance(obj, dict) and "completed" in obj:
            return obj
        idx = raw.find("{", end)
    return None


def _extract_longcat_commands(response: str) -> list:
    cmds = []
    for block in re.findall(r'<longcat_tool_call>(.*?)(?:</longcat_tool_call>|\Z)', response, re.DOTALL | re.IGNORECASE):
        m = re.search(
            r'<longcat_arg_key>\s*(?:command|cmd|shell)\s*</longcat_arg_key>\s*'
            r'<longcat_arg_value>\s*(.*?)\s*(?:</longcat_arg_value>|</longcat_tool_call>|<longcat_arg_key>|\Z)',
            block, re.DOTALL | re.IGNORECASE,
        )
        if m and m.group(1).strip():
            cmds.append(m.group(1).strip())
    return cmds


def _extract_prose_command(raw: str) -> str:
    if not raw:
        return ""
    # EXEC: directive
    for line in raw.splitlines():
        s = line.strip()
        if s.upper().startswith("EXEC:"):
            cmd = s.split(":", 1)[1].strip()
            if cmd:
                return cmd
    # Fenced code block
    for fence in ("```bash", "```sh", "```shell", "```"):
        m = re.search(re.escape(fence) + r"\s*\n(.*?)```", raw, re.DOTALL | re.IGNORECASE)
        if m:
            for line in m.group(1).splitlines():
                s = line.strip()
                if s and not s.startswith("#"):
                    return s
    # Inline backtick
    bticks = re.findall(r'`([^`\n]{8,400})`', raw)
    for cand in bticks:
        s = cand.strip().strip("$").strip()
        if re.match(r'^(nmap|curl|wget|httpx|sqlmap|nuclei|ffuf|gobuster|feroxbuster|whatweb|masscan|rustscan|hydra|nc|cat|ls|cd|bash|sh|python|python3)\s', s, re.IGNORECASE):
            return s
    return ""


def _normalize_decision(d: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(d, dict) or "completed" not in d:
        return None
    d["completed"] = bool(d.get("completed"))
    nc = d.get("next_command")
    d["next_command"] = nc.strip() if isinstance(nc, str) else ""
    if not isinstance(d.get("finding"), dict):
        d["finding"] = None
    if not isinstance(d.get("plan"), dict):
        d["plan"] = None
    for k in ("thinking", "think", "reasoning", "strategy", "pivot_reason"):
        v = d.get(k)
        d[k] = v if isinstance(v, str) else ("" if v is None else str(v))
    return d
