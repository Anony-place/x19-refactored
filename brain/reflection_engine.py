"""Reflection engine extracted from agent.py.

Analyzes command outcomes and produces structured self-reflection text
that can be injected into LLM context for better decision-making.
"""

from __future__ import annotations

import re
from typing import List


def reflect_on_command(command: str, output: str, returncode: int) -> str:
    """Analyze what happened with the last command and generate reflection.

    Richer than the original: adds quantitative assessment and pivot suggestions.
    """
    if not command:
        return ""

    parts: List[str] = []
    cmd_lower = command.lower()

    # ===================== overall outcome =====================
    if returncode == 0:
        parts.append("OUTCOME: SUCCESS — command completed without errors.")
    elif returncode == -1:
        parts.append("OUTCOME: FAILURE — timeout or execution error.")
    else:
        parts.append(f"OUTCOME: FAILURE (rc={returncode}).")

    # ===================== output quality =====================
    blob = (output or "").strip()
    if not blob:
        parts.append("OUTPUT: empty — no data returned.")
    elif len(blob) < 50:
        parts.append("OUTPUT: very short — likely no useful data.")
    elif _looks_like_error_blob(blob):
        parts.append("OUTPUT: appears to be primarily an error message.")
    else:
        parts.append(f"OUTPUT: {len(blob)} chars of potentially useful data.")

    # ===================== failure analysis =====================
    if returncode != 0:
        stderr_lower = blob.lower()
        if any(p in stderr_lower for p in ["not found", "command not found", "no such file", "could not find"]):
            parts.append("FAILURE_CAUSE: missing tool or file — install or correct path.")
        elif any(p in stderr_lower for p in ["timeout", "timed out"]):
            parts.append("FAILURE_CAUSE: timeout — use simpler scan, smaller scope, or longer timeout.")
        elif any(p in stderr_lower for p in ["permission denied", "denied"]):
            parts.append("FAILURE_CAUSE: permission denied — try sudo, different user, or alternate approach.")
        elif any(p in stderr_lower for p in ["connection refused", "could not connect", "failed to connect", "couldn't connect"]):
            parts.append("FAILURE_CAUSE: connection refused — service may not be running on that port.")
        elif any(p in stderr_lower for p in ["resolve", "could not resolve", "name or service not known", "temporary failure"]):
            parts.append("FAILURE_CAUSE: DNS resolution failed — check hostname or use IP directly.")
        elif "429" in stderr_lower or "rate limit" in stderr_lower:
            parts.append("FAILURE_CAUSE: rate-limited — slow down, rotate user-agent, or use different source.")
        else:
            parts.append("FAILURE_CAUSE: unknown — try different tool or approach (avoid repeating same command).")

    # ===================== signal extraction =====================
    signals: List[str] = []
    urls = re.findall(r'https?://[^\s<>"\'\[\]]+', blob)[:5]
    if urls:
        signals.append(f"{len(urls)} URL(s)")
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', blob)[:5]
    if ips:
        signals.append(f"{len(ips)} IP(s)")
    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', blob)[:3]
    if emails:
        signals.append(f"{len(emails)} email(s)")
    ports = re.findall(r'(\d+)/(?:tcp|udp)\s+open', blob)[:5]
    if ports:
        signals.append(f"{len(ports)} open port(s)")
    versions = re.findall(r'\b\d+\.\d+(?:\.\d+)*\b', blob)[:3]
    if versions:
        signals.append(f"version hints: {', '.join(versions)}")
    if signals:
        parts.append("SIGNALS: " + ", ".join(signals) + ".")

    # ===================== pivot recommendation =====================
    if returncode != 0:
        if "not found" in blob.lower():
            parts.append("PIVOT: install the missing tool or choose an alternative already available.")
        elif "timeout" in blob.lower():
            parts.append("PIVOT: reduce scope (top-ports instead of -p-), or switch to async/lighter tool.")
        elif "connection refused" in blob.lower():
            parts.append("PIVOT: verify the service is actually running; try a different port or protocol.")
        else:
            parts.append("PIVOT: choose a different tool category (do not repeat the same command).")

    return " | ".join(parts)


def _looks_like_error_blob(blob: str) -> bool:
    lower = blob.lower()
    error_headers = [
        "error:", "exception", "traceback", "failed", "denied",
        "not found", "usage:", "command not found", "no such file",
    ]
    lines = lower.splitlines()
    if not lines:
        return False
    match_count = sum(1 for h in error_headers if h in lines[0])
    return match_count >= 1 or lower.count("error") >= 3
