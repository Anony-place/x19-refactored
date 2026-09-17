"""Deprecated shim — prefer `python run.py`.

`python -m x19` / `python x19.py` still work for cron/CI backward compat but
print a one-line deprecation hint pointing at the single supported entry.
"""
from run import main
import sys

if __name__ == "__main__":
    if "--help" not in sys.argv and "-h" not in sys.argv:
        print("[x19] note: `python x19.py` is an alias — prefer `python run.py` (single supported entry).",
              file=sys.stderr)
    raise SystemExit(main())
