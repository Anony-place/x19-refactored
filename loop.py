import json
import os
import re
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass, field, asdict

from constants import C, ICO
from config import CONFIG, CONFIG_DIR, load_config
from logging_utils import log


# ---- Regex patterns used by helpers -------------------------------------------

_TIMESTAMP_RE = re.compile(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b')
_EPOCH_RE    = re.compile(r'\b1[6-9]\d{8,9}\b')                    # epoch seconds (10-11 digits, post-2016)
_UUID_RE     = re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.I)
_REQ_ID_RE   = re.compile(r'\breq[_-]?id["\s:=]+[a-z0-9\-]{8,}\b', re.I)
_TRACE_ID_RE = re.compile(r'\btrace[_-]?id["\s:=]+[a-z0-9\-]{8,}\b', re.I)
_SHA_RE      = re.compile(r'\b[0-9a-f]{32,64}\b', re.I)
_IPV4_RE     = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_URL_PATH_RE = re.compile(r'^https?://[^\s/?#]+(/[^\s?#]*)')  # capture URL path

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


# ---- LoopSignal (from py:5286) --------------------------------------------

@dataclass
class LoopSignal:
    state: str = "none"  # none|soft|hard
    category: str = ""   # derived/stagnant category
    reason: str = ""


# ---- Helper functions (from py:6610) ---------------------------------------

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
    tmpdir = tempfile.gettempdir().replace("\\", "/")
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
            # Collapse path numbers (e.g. /users/1, /users/2 -> /users/N)
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


# ---- AntiLoop classes (from py:6693) ---------------------------------------

@dataclass
class AntiLoopState:
    """Mutable state for the AntiLoopEngine. Persisted via JsonFileStore per session."""
    output_fingerprints: List[str] = field(default_factory=list)   # last 20 fingerprints
    command_signatures: Dict[str, int] = field(default_factory=dict) # sig -> count
    endpoint_tool_hits: Dict[str, int] = field(default_factory=dict) # "tool|url_path" -> count
    progress_streak: int = 0       # consecutive turns WITH progress
    noise_streak: int = 0          # consecutive turns WITHOUT progress
    total_useful: int = 0
    total_noise: int = 0
    last_categories: List[str] = field(default_factory=list)  # last 8 categories
    last_tools: List[str] = field(default_factory=list)       # last 8 tool names
    halt_reason: str = ""          # set when circuit breaker trips
    halted: bool = False
    # For finding-summary diff: we expose "session_growth" so LLM context can say
    # "you've added 0 endpoints in the last 6 turns — stop scanning, start exploiting"
    last_progress_ts: float = 0.0
    # Tool failure tracking: tool_name -> list of (error_type, timestamp)
    tool_failure_history: Dict[str, List[Tuple[str, float]]] = field(default_factory=dict)
    # Session memory: tool+flag signatures that failed in last 3 iterations
    recent_failed_signatures: List[str] = field(default_factory=list)  # max 20 entries
    failed_signature_count: Dict[str, int] = field(default_factory=dict)


class AntiLoopEngine:
    """Stronger loop detection + circuit breaker.
    Tracks 5 signals:
      (a) Output fingerprint repetition (normalized, ignores timestamps)
      (b) Command signature repetition (tool + target + wordlist)
      (c) Endpoint + tool family revisits
      (d) Progress streak (consecutive turns that added a finding/endpoint/port)
      (e) Adaptive category / tool diversity (last 8 of each)
    Returns LoopSignal-compatible (state, category, reason) but with tighter
    thresholds and a session-level circuit breaker."""

    HARD_REPEAT_THRESHOLD   = 8   # same fingerprint 8x in last 20 = HARD loop
    SOFT_REPEAT_THRESHOLD   = 5   # same fingerprint 5x = SOFT loop
    SIG_COUNT_HARD          = 12  # same cmd signature 12x = HARD
    ENDPOINT_REVISIT_HARD   = 10  # same (tool, url) 10x = HARD
    NOISE_STREAK_HARD       = 15  # 15 turns of zero progress = HARD
    NOISE_STREAK_SOFT       = 8   # 8 turns of zero progress = SOFT
    CATEGORY_REPEAT_HARD    = 6   # same category 6 turns in a row = HARD
    TOOL_REPEAT_HARD        = 5   # same tool 5 turns in a row (within last 8) = HARD
    PROGRESS_FLOOR          = 0.15  # min ratio of useful/total over last 10 turns

    def __init__(self, state_path: Path = None):
        self.state_path = state_path or (CONFIG_DIR / "antiloop.json")
        self._lock = threading.RLock()
        self.state = self._load()

    def _load(self) -> AntiLoopState:
        if not self.state_path.exists():
            return AntiLoopState()
        try:
            d = json.loads(self.state_path.read_text(encoding="utf-8"))
            st = AntiLoopState()
            for k, v in d.items():
                if hasattr(st, k):
                    setattr(st, k, v)
            return st
        except Exception:
            return AntiLoopState()

    def _save(self):
        try:
            tmp = self.state_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(asdict(self.state), default=str), encoding="utf-8")
            tmp.replace(self.state_path)
        except Exception as e:
            log(f"[AntiLoop] save failed: {e}")

    def reset(self):
        """Reset all loop-tracking state. Call on a brand-new target or session."""
        with self._lock:
            self.state = AntiLoopState()
            self._save()

    def observe(self, command: str, category: str, output: str,
                before_count: int, after_count: int) -> LoopSignal:
        """Record one step and return a LoopSignal. NEVER raises."""
        try:
            return self._observe_safe(command, category, output, before_count, after_count)
        except Exception as e:
            log(f"[AntiLoop] observe error: {e}")
            return LoopSignal(state="none", reason="antiloop-error")

    def _observe_safe(self, command, category, output, before_count, after_count) -> LoopSignal:
        with self._lock:
            sig = signature_command(command)
            fp  = fingerprint_output(output)
            tool = (command.strip().split() or [""])[0].lower()

            # 1) Update output fingerprint ring (keep last 20)
            self.state.output_fingerprints.append(fp)
            self.state.output_fingerprints = self.state.output_fingerprints[-20:]

            # 2) Bump command signature count
            if sig:
                self.state.command_signatures[sig] = self.state.command_signatures.get(sig, 0) + 1

            # 3) Bump endpoint + tool revisits
            m = re.search(r'https?://[^\s/]+(/\S*)?', command, re.I)
            if m and tool:
                path = m.group(0).split('?', 1)[0]
                path = re.sub(r'/\d+', '/N', path)
                key = f"{tool}|{path}"
                self.state.endpoint_tool_hits[key] = self.state.endpoint_tool_hits.get(key, 0) + 1

            # 4) Update progress
            is_useful, delta = classify_progress(output, before_count, after_count)
            if is_useful:
                self.state.progress_streak += 1
                self.state.noise_streak = 0
                self.state.total_useful += max(1, delta)
                self.state.last_progress_ts = time.time()
            else:
                self.state.progress_streak = 0
                self.state.noise_streak += 1
                self.state.total_noise += 1

            # 5) Update category / tool trails
            if category:
                self.state.last_categories.append(category)
                self.state.last_categories = self.state.last_categories[-8:]
            if tool:
                self.state.last_tools.append(tool)
                self.state.last_tools = self.state.last_tools[-8:]

            self._save()

            # ------- Detection logic -------
            # (a) Hard: same output fingerprint repeated HARD_REPEAT_THRESHOLD times in last 12
            #     (count includes the current observation; need >= 2 to be a real repeat)
            recent_fp = self.state.output_fingerprints[-12:]
            # count of PAST occurrences (excluding the just-pushed one)
            past_count = (recent_fp.count(fp) - 1) if fp else 0
            if fp and past_count >= self.HARD_REPEAT_THRESHOLD:
                self.state.halted = True
                self.state.halt_reason = f"Output fingerprint repeated {recent_fp.count(fp)}x in last {len(recent_fp)} turns"
                return LoopSignal(state="hard", category=category or "noise", reason=self.state.halt_reason)
            if fp and past_count >= self.SOFT_REPEAT_THRESHOLD:
                return LoopSignal(state="soft", category=category or "noise",
                                  reason=f"Output fingerprint repeated {recent_fp.count(fp)}x recently")

            # (b) Hard: command signature seen SIG_COUNT_HARD+ times
            if sig and self.state.command_signatures.get(sig, 0) >= self.SIG_COUNT_HARD:
                self.state.halted = True
                self.state.halt_reason = f"Command signature '{sig}' used {self.state.command_signatures[sig]}x — aborting"
                return LoopSignal(state="hard", category=category or "repeat", reason=self.state.halt_reason)

            # (c) Hard: same (tool, endpoint) hit too many times
            worst_hit = max(self.state.endpoint_tool_hits.values()) if self.state.endpoint_tool_hits else 0
            if worst_hit >= self.ENDPOINT_REVISIT_HARD:
                worst_key = max(self.state.endpoint_tool_hits, key=self.state.endpoint_tool_hits.get)
                return LoopSignal(state="hard", category=category or "revisit",
                                  reason=f"Same endpoint '{worst_key}' hit {worst_hit} times")

            # (d) Hard: long noise streak
            if self.state.noise_streak >= self.NOISE_STREAK_HARD:
                self.state.halted = True
                self.state.halt_reason = f"No progress for {self.state.noise_streak} consecutive turns"
                return LoopSignal(state="hard", category=category or "stagnation", reason=self.state.halt_reason)
            if self.state.noise_streak >= self.NOISE_STREAK_SOFT:
                return LoopSignal(state="soft", category=category or "stagnation",
                                  reason=f"No progress for {self.state.noise_streak} consecutive turns")

            # (e) Category stuck
            cat_run = 0
            for c in reversed(self.state.last_categories):
                if c == category:
                    cat_run += 1
                else:
                    break
            if cat_run >= self.CATEGORY_REPEAT_HARD:
                return LoopSignal(state="hard", category=category or "category-stuck",
                                  reason=f"Category '{category}' repeated {cat_run}x — pivot required")

            # (f) Tool stuck (within last 8)
            tool_run = 0
            for t in reversed(self.state.last_tools):
                if t == tool:
                    tool_run += 1
                else:
                    break
            if tool_run >= self.TOOL_REPEAT_HARD:
                return LoopSignal(state="soft", category=category or "tool-stuck",
                                  reason=f"Tool '{tool}' used {tool_run}x in a row — pick a different tool")

            return LoopSignal(state="none", reason="")

    def is_halted(self) -> Tuple[bool, str]:
        with self._lock:
            return self.state.halted, self.state.halt_reason

    def record_tool_failure(self, tool_name: str, error_type: str):
        """Track a tool failure with its error type. Used to detect consecutive same-error failures."""
        with self._lock:
            now = time.time()
            history = self.state.tool_failure_history.setdefault(tool_name, [])
            history.append((error_type, now))
            # Keep last 20 entries
            history[:] = history[-20:]

    def has_consecutive_same_error(self, tool_name: str, error_type: str, threshold: int = 2) -> bool:
        """Check if a tool has failed N+ times consecutively with the same error type."""
        with self._lock:
            history = self.state.tool_failure_history.get(tool_name, [])
            if len(history) < threshold:
                return False
            recent = history[-threshold:]
            return all(err == error_type for err, _ in recent)

    def record_failed_signature(self, sig: str):
        """Record a tool+flag signature that just failed."""
        with self._lock:
            self.state.recent_failed_signatures.append(sig)
            self.state.recent_failed_signatures = self.state.recent_failed_signatures[-20:]
            self.state.failed_signature_count[sig] = self.state.failed_signature_count.get(sig, 0) + 1

    def is_signature_blocked(self, sig: str, max_recent: int = 3) -> bool:
        """Check if this exact tool+flag signature failed in the last N iterations."""
        with self._lock:
            count = self.state.failed_signature_count.get(sig, 0)
            if count >= max_recent:
                return True
            recent = self.state.recent_failed_signatures[-3:]
            return sig in recent

    def get_recent_failed_tools(self) -> List[str]:
        """Return tool names that have failed in this session."""
        with self._lock:
            return list(self.state.tool_failure_history.keys())

    def summary(self) -> str:
        """Short human-readable status for LLM context."""
        s = self.state
        total = s.total_useful + s.total_noise
        ratio = (s.total_useful / total * 100.0) if total else 0.0
        return (f"AntiLoop: useful={s.total_useful} noise={s.total_noise} "
                f"({ratio:.0f}% useful), progress_streak={s.progress_streak}, "
                f"noise_streak={s.noise_streak}, "
                f"halted={s.halted}")


# Module-level singleton
_ANTILOOP_SINGLETON: Optional[AntiLoopEngine] = None


def get_antiloop() -> AntiLoopEngine:
    global _ANTILOOP_SINGLETON
    if _ANTILOOP_SINGLETON is None:
        _ANTILOOP_SINGLETON = AntiLoopEngine()
    return _ANTILOOP_SINGLETON


# ---- Hypothesis classes (from py:6930) -------------------------------------

@dataclass
class HypothesisState:
    key: str
    state: str = "NEW"
    score: float = 0.8
    attempts: int = 0
    prior_evidence_hashes: list = field(default_factory=list)
    last_tested_iteration: int = 0
    confirmed_finding_title: str = ""
    rejection_reason: str = ""


HYP_STATE_NEW = "NEW"
HYP_STATE_TESTING = "TESTING"
HYP_STATE_CONFIRMED = "CONFIRMED"
HYP_STATE_REJECTED = "REJECTED"
HYP_STATE_DEAD = "DEAD"
HYP_STATE_STALE = "STALE"

HYP_SCORE_REDUCE_THRESHOLD = 3
HYP_DEAD_THRESHOLD = 5
HYP_STALE_ITERATIONS = 15


@dataclass
class StructuredHypothesis:
    """A specific, testable hypothesis generated by the engine."""
    title: str
    service: str
    technique: str
    command: str
    expected: str
    interpretation: str
    port: int = 0
    priority: float = 0.5
    cve: str = ""
    tested: bool = False


@dataclass
class GateResult:
    name: str
    passed: bool
    reason: str = ""


@dataclass
class ValidationResult:
    is_confirmed: bool
    classification: str
    failed_gates: list
    explanation: str
