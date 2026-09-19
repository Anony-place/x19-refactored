"""Durable persistence helpers for X19 organizational state.

Organizational state (task graph, agent roster history, event stream, approval
decisions) is deliberately kept **separate** from conversation state: the chat
history is a transcript, the org state is the operating record.  They live in
different places and have different lifecycles.

Layout under ``X19_HOME/org/``::

    org/
      state.json      task graph + objective metadata (atomic replace)
      events.jsonl    append-only audit stream
      approvals.json  pending / resolved human decisions
      run.json        current run: objective, phase, start time

Every write is atomic (tmp + ``os.replace``) so a crash mid-write cannot leave a
half-written operating record behind.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

__all__ = [
    "org_root",
    "state_path",
    "events_path",
    "approvals_path",
    "run_path",
    "atomic_write_json",
    "read_json",
    "append_jsonl",
]

_LOCK = threading.RLock()


def org_root(override: Optional[os.PathLike[str] | str] = None) -> Path:
    """``X19_HOME/org`` — resolved through the real config layer when available."""
    if override is not None:
        return Path(override)
    env = os.environ.get("X19_ORG_DIR")
    if env:
        return Path(env)
    try:
        from x19_cli.config import get_x19_home

        return Path(get_x19_home()) / "org"
    except Exception:
        home = os.environ.get("X19_HOME")
        if home:
            return Path(home) / "org"
        return Path.home() / ".x19" / "org"


def state_path(root: Optional[Path] = None) -> Path:
    return (root or org_root()) / "state.json"


def events_path(root: Optional[Path] = None) -> Path:
    return (root or org_root()) / "events.jsonl"


def approvals_path(root: Optional[Path] = None) -> Path:
    return (root or org_root()) / "approvals.json"


def run_path(root: Optional[Path] = None) -> Path:
    return (root or org_root()) / "run.json"


def atomic_write_json(path: os.PathLike[str] | str, payload: Any) -> bool:
    """Write JSON atomically.  Returns False (never raises) on I/O failure."""
    p = Path(path)
    with _LOCK:
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_name(p.name + f".tmp.{os.getpid()}")
            tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=None), encoding="utf-8")
            os.replace(tmp, p)
            return True
        except OSError:
            try:
                if tmp.exists():
                    tmp.unlink()
            except Exception:
                pass
            return False


def read_json(path: os.PathLike[str] | str, default: Any = None) -> Any:
    p = Path(path)
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def append_jsonl(path: os.PathLike[str] | str, record: Dict[str, Any]) -> bool:
    p = Path(path)
    with _LOCK:
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            return True
        except OSError:
            return False


def now() -> float:
    return time.time()
