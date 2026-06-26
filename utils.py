import hashlib
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any

from constants import C, ICO, SYSTEM_PROMPT, FAST_DECISION_PROMPT, LEAN_SYSTEM_PROMPT, LEAN_FAST_PROMPT
from config import CONFIG, load_config


_X19_BROWSER_CLI = f'"{sys.executable}" "{os.path.abspath(__file__)}" --browser'
_BROWSER_HINT = (
    "\n\nBROWSER AUTOMATION (headless Chrome via Selenium) — use for JS-heavy/SPA pages where curl/httpx "
    "return little or empty content:\n"
    f"  {_X19_BROWSER_CLI} forms --url <URL>       # links + forms/inputs after JS renders\n"
    f"  {_X19_BROWSER_CLI} render --url <URL>      # final rendered DOM\n"
    f"  {_X19_BROWSER_CLI} screenshot --url <URL>  # full-page screenshot\n"
    "Run these as normal next_command shell commands."
)


def is_bug_bounty_mode() -> bool:
    return CONFIG.BUG_BOUNTY_MODE or os.getenv("X19_BUG_BOUNTY_MODE", "").strip().lower() in ("1", "true", "yes")


def is_ctf_mode() -> bool:
    """CTF mode: aggressive exploitation, flag hunting, full testing."""
    return CONFIG.CTF_MODE or os.getenv("X19_CTF_MODE", "").strip().lower() in ("1", "true", "yes")


def is_fast_mode() -> bool:
    """Faster planning/decisions: compact prompt, smaller context, no extra LLM verify."""
    if CONFIG.FAST_MODE or os.getenv("X19_FAST_MODE", "").strip().lower() in ("1", "true", "yes"):
        return True
    return is_bug_bounty_mode() or is_ctf_mode()


def decision_system_prompt() -> str:
    intel_mode = os.getenv("X19_INTEL_MODE", "lean").strip().lower()
    if intel_mode == "legacy":
        base = FAST_DECISION_PROMPT if is_fast_mode() else SYSTEM_PROMPT
    else:
        base = LEAN_FAST_PROMPT if is_fast_mode() else LEAN_SYSTEM_PROMPT
    return base + _BROWSER_HINT


def live_type(text, delay=0.003):
    """Print a line of agent output instantly (no typing animation — standard CLI behavior).
    `delay` is accepted for backward compatibility with existing call sites."""
    print(text, flush=True)


def _ver_lt(a: str, b: str) -> bool:
    """Loose semver-ish less-than comparison. 2.4.49 < 2.4.50; 2.14.0 < 2.15.0."""
    def _parts(v):
        out = []
        for p in re.split(r'[.\-_]', v.strip()):
            m = re.match(r'(\d+)(.*)', p)
            if m:
                out.append((int(m.group(1)), m.group(2)))
            else:
                out.append((0, p))
        return out
    try:
        return _parts(a) < _parts(b)
    except Exception:
        return False


def _ver_in_range(v: str, lo: str, hi: str) -> bool:
    return _ver_lt(lo, v) and _ver_lt(v, hi)


_TIMESTAMP_RE = re.compile(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b')
_EPOCH_RE    = re.compile(r'\b1[6-9]\d{8,9}\b')                    # epoch seconds (10-11 digits, post-2016)
_UUID_RE     = re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.I)
_REQ_ID_RE   = re.compile(r'\breq[_-]?id["\s:=]+[a-z0-9\-]{8,}\b', re.I)
_TRACE_ID_RE = re.compile(r'\btrace[_-]?id["\s:=]+[a-z0-9\-]{8,}\b', re.I)
_SHA_RE      = re.compile(r'\b[0-9a-f]{32,64}\b', re.I)
_IPV4_RE     = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# Words that indicate "I found something new" in command output
_USEFUL_KEYWORDS = re.compile(
    r'\b('
    r'vulnerab|exploit|inject|sql|xss|csrf|ssrf|idor|rce|lfi|rfi|xxe|'
    r'credential|password|secret|token|api[_-]?key|bearer|'
    r'open port|service detected|version|discovered|'
    r'new endpoint|status[ _-]?code[":= ]+[2-5]\d\d|'
    r'CVE-\d{4}-\d+|'
    r'admin|root|private key|'
    r'www\.|\.com|\.net|\.io|\.dev'
    r')\b', re.I)
# Words that indicate "no new info" — empty scan, no results, all 404s, etc.
_NOISE_KEYWORDS = re.compile(
    r'\b('
    r'no (?:results|findings|matches|endpoints|output|hosts|response|such file|connections),?|'
    r'nothing found|'
    r'0 (?:results|findings|matches|vulnerab|endpoints),?|'
    r'(?:all|every) (?:requests?|urls?) returned [45]\d\d|'
    r'no live targets|'
    r'0%|'
    r'finished after 0|'
    r'^\s*$'
    r')', re.I | re.M)


def fingerprint_output(text: str, max_len: int = 4000) -> str:
    """Normalize command output into a stable fingerprint.
    Strips timestamps, uuids, request-ids, sha hashes, ipv4 — keeps structure so
    'same scan, different timestamp' / 'same scan, different request-id' both
    collapse to the same fingerprint."""
    if not text:
        return ""
    t = text[:max_len]
    t = _TIMESTAMP_RE.sub('TS', t)
    t = _EPOCH_RE.sub('TS', t)
    t = _UUID_RE.sub('UUID', t)
    t = _REQ_ID_RE.sub('REQ_ID', t)
    t = _TRACE_ID_RE.sub('TRACE_ID', t)
    t = _SHA_RE.sub('SHA', t)
    # Keep ipv4 only in URLs (collapse all other IP mentions)
    t = _IPV4_RE.sub('IP', t)
    t = re.sub(r'\s+', ' ', t).strip()
    return t[:512]


def signature_command(command: str) -> str:
    """Tool+target+flags signature. 'ffuf -u http://t.com/api/users/1 -w w.txt' and
    'ffuf -u http://t.com/api/users/2 -w w.txt' both become 'ffuf:/api/users/*:w.txt'.
    For nmap, the -p flag IS part of the signature (so 'nmap -p 22 X' and 'nmap -p 80 X'
    are different probes, not duplicates). Other tools: tool+target+wordlist is enough."""
    if not command:
        return ""
    s = command.strip()
    tmpdir = __import__("tempfile").gettempdir().replace("\\", "/")
    s = re.sub(re.escape(tmpdir) + r'/[a-zA-Z0-9_\.\-]+', tmpdir + '/_', s)
    s = re.sub(r'\s+', ' ', s)
    # Extract first tool + first URL/host + first wordlist, drop the rest
    m = re.match(r'^(\S+)', s)
    tool = (m.group(1).lower() if m else "")
    # Find URL or target
    target = ""
    for pat in (r'https?://[^\s/]+(/\S*)?', r'-u\s+(\S+)', r'-d\s+(\S+)', r'-t\s+(\S+)', r'(?:^|\s)([a-z0-9\-\.]+\.[a-z]{2,})(?:[\s/:]|$)'):
        m = re.search(pat, s, re.I)
        if m:
            target = m.group(0) if isinstance(m.group(0), str) else (m.group(1) or "")
            # Strip query for URL dedup
            if '?' in target:
                target = target.split('?', 1)[0]
            # Collapse path numbers (e.g. /users/1, /users/2 → /users/N)
            target = re.sub(r'/\d+', '/N', target)
            # Collapse path UUIDs
            target = re.sub(r'/[0-9a-f]{8}-[0-9a-f-]{27,}', '/UUID', target, flags=re.I)
            break
    # Wordlist
    wlist = ""
    m = re.search(r'-w\s+(\S+)', s)
    if m:
        wlist = m.group(1).split('/')[-1]  # basename only
    # nmap: include -p flag so different port-scans dedupe correctly
    if tool in ("nmap", "rustscan", "masscan"):
        pm = re.search(r'(?:^|\s)-p\s*([\w,\-\s]+?)(?=\s+\S|$)', s)
        if pm:
            ports = pm.group(1).strip().replace(" ", "")
            return f"{tool}|{target}|p={ports}|{wlist}"
    return f"{tool}|{target}|{wlist}"


def classify_progress(text: str, before_count: int, after_count: int) -> Tuple[bool, int]:
    """Classify command output as USEFUL (progress) or NOISE (no progress).
    Returns (is_useful, delta_count) where delta_count = new findings/endpoints in output."""
    if not text:
        return False, 0
    delta = max(0, after_count - before_count)
    # If anything new was discovered, that's progress
    if delta > 0:
        return True, delta
    # Heuristic: scan for "useful" / "noise" signals
    has_useful = bool(_USEFUL_KEYWORDS.search(text))
    has_noise  = bool(_NOISE_KEYWORDS.search(text))
    # If only noise signals, no progress
    if has_noise and not has_useful:
        return False, 0
    # If useful signal AND not noise, count as 1 unit of progress
    if has_useful:
        return True, 1
    # Ambiguous: count as 0.5 — neither strong progress nor hard noise
    return False, 0


# Placeholder/default targets that must never be scanned implicitly.
_DEFAULT_TARGETS = {"", "0.0.0.0", "127.0.0.1", "localhost", "*", "::", "::1", "::/0", "0.0.0.0/0"}


def validate_target(target: str) -> str:
    """Reject missing targets and require explicit confirmation for placeholder/default values.

    Raises ValueError instead of silently substituting a default (empty, 0.0.0.0, localhost, *, ...).
    """
    t = (target or "").strip()
    if t.lower() in _DEFAULT_TARGETS:
        if not t:
            raise ValueError(
                "No target specified. Refusing to run against a default — pass an explicit host (e.g. 'target example.com')."
            )
        if not sys.stdin.isatty():
            raise ValueError(
                f"Refusing to run against placeholder/default target '{t}' without explicit confirmation."
            )
        if input(f"{C.R}[!] '{t}' is a placeholder/default target. Re-type it to confirm: {C.N}").strip() != t:
            raise ValueError(f"Target '{t}' not confirmed. Aborting.")
    return t


def _parse_ints(val: str) -> List[int]:
    if not val:
        return []
    out = []
    for p in val.replace(" ", "").split(","):
        if p:
            try:
                out.append(int(p))
            except ValueError:
                pass
    return out
