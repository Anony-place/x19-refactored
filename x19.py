"""Module entry point used by durable X19 cron jobs.

Keeping this tiny shim means `python -m x19 <command>` behaves exactly like
`python run.py <command>` without changing the existing package layout.
"""
from run import main


if __name__ == "__main__":
    raise SystemExit(main())
