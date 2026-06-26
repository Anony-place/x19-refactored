from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Dict, Any


_FAILURES: Dict[str, int] = {}  # site "func:line" -> swallowed-exception count (failure tracking)


def log(entry: str, *, log_file: str | None = None):
    """
    Append a timestamped line into the agent log file.

    If log_file is not provided, caller should pass x19.config.CONFIG.LOG_FILE.
    """
    if not log_file:
        try:
            from config import CONFIG
            log_file = CONFIG.LOG_FILE
        except Exception:
            log_file = str(Path(".") / "x19_agent.log")

    p = Path(log_file)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(f"[{datetime.now().isoformat()}] {entry}\n")


def swallow(e: BaseException):
    import traceback

    msg = f"{type(e).__name__}: {e}"
    # Suppress harmless interpreter-shutdown noise
    if isinstance(e, RuntimeError) and "cannot schedule new futures" in msg:
        return
    if isinstance(e, RuntimeError) and "shutdown" in msg.lower():
        return

    s = traceback.extract_stack()
    fr = s[-2] if len(s) >= 2 else s[-1]
    site = f"{fr.name}:{fr.lineno}"
    _FAILURES[site] = _FAILURES.get(site, 0) + 1
    log(f"[SWALLOWED] {site} (#{_FAILURES[site]}) {msg}")


def get_swallow_failures() -> Dict[str, Any]:
    return dict(_FAILURES)
