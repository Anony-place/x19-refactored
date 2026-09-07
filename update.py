#!/usr/bin/env python3
"""Safe in-place updater for X19.

Usage:
    python update.py
    python update.py --check
    python update.py --force
    python update.py --no-deps

The updater intentionally refuses to overwrite local work unless --force is
explicitly supplied. With --force, tracked and untracked local changes are
stashed before updating and are never silently deleted.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


class UpdateError(RuntimeError):
    pass


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        list(args),
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        raise UpdateError(f"Command failed: {' '.join(args)}\n{detail}")
    return proc


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run("git", *args, check=check)


def ensure_repo() -> None:
    if shutil.which("git") is None:
        raise UpdateError("git is not installed or not available in PATH.")
    if not (ROOT / ".git").exists():
        raise UpdateError(
            "This X19 copy is not a Git clone (.git is missing). "
            "Clone the repository once; future updates can use update.py."
        )


def current_branch() -> str:
    branch = git("branch", "--show-current").stdout.strip()
    if not branch:
        raise UpdateError("Detached HEAD detected. Switch to a branch before updating.")
    return branch


def upstream_for(branch: str) -> str:
    proc = git("rev-parse", "--abbrev-ref", f"{branch}@{{upstream}}", check=False)
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    # Normal clones generally use origin/<branch>. Verify it exists before use.
    candidate = f"origin/{branch}"
    if git("rev-parse", "--verify", candidate, check=False).returncode == 0:
        return candidate
    raise UpdateError(
        f"No upstream configured for branch '{branch}'. "
        f"Set one with: git branch --set-upstream-to=origin/{branch} {branch}"
    )


def dirty() -> bool:
    return bool(git("status", "--porcelain").stdout.strip())


def stash_local_changes() -> bool:
    if not dirty():
        return False
    proc = git("stash", "push", "--include-untracked", "-m", "x19-update-auto-backup")
    if proc.returncode != 0:
        raise UpdateError(f"Could not back up local changes:\n{proc.stderr.strip()}")
    return True


def fetch() -> None:
    print("[*] Fetching updates...")
    git("fetch", "--prune", "origin")


def ahead_behind(upstream: str) -> tuple[int, int]:
    raw = git("rev-list", "--left-right", "--count", f"HEAD...{upstream}").stdout.strip()
    try:
        ahead, behind = (int(x) for x in raw.split())
    except (ValueError, TypeError):
        raise UpdateError(f"Could not determine update status: {raw!r}")
    return ahead, behind


def install_dependencies() -> None:
    req = ROOT / "requirements.txt"
    if not req.exists():
        print("[*] requirements.txt not found; skipping dependency update.")
        return
    print("[*] Updating Python dependencies...")
    run(sys.executable, "-m", "pip", "install", "-r", str(req))


def sanity_check() -> None:
    print("[*] Running Python syntax/import compilation check...")
    proc = run(sys.executable, "-m", "compileall", "-q", str(ROOT), check=False)
    if proc.returncode != 0:
        raise UpdateError(
            "Update downloaded, but Python compilation check failed.\n"
            + (proc.stderr or proc.stdout).strip()
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Update an existing X19 Git clone safely")
    parser.add_argument("--check", action="store_true", help="Only check whether updates are available")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Back up local changes to git stash and continue instead of refusing",
    )
    parser.add_argument("--no-deps", action="store_true", help="Do not run pip install -r requirements.txt")
    args = parser.parse_args()

    try:
        ensure_repo()
        branch = current_branch()
        fetch()
        upstream = upstream_for(branch)
        ahead, behind = ahead_behind(upstream)

        print(f"[*] Branch: {branch}")
        print(f"[*] Upstream: {upstream}")
        print(f"[*] Local commits ahead: {ahead}")
        print(f"[*] Remote commits available: {behind}")

        if args.check:
            print("[+] Update available." if behind else "[+] X19 is already up to date.")
            return 0

        if behind == 0:
            print("[+] X19 is already up to date.")
            return 0

        if ahead:
            raise UpdateError(
                "Local branch contains commits not present upstream. "
                "Refusing an automatic update; merge/rebase them manually first."
            )

        was_stashed = False
        if dirty():
            if not args.force:
                raise UpdateError(
                    "Local changes detected. Commit/stash them first, or rerun with --force "
                    "to create an automatic stash backup."
                )
            print("[*] Local changes detected; creating safety stash...")
            was_stashed = stash_local_changes()

        print("[*] Applying update (fast-forward only)...")
        git("merge", "--ff-only", upstream)

        if not args.no_deps:
            install_dependencies()
        sanity_check()

        print("[+] X19 updated successfully.")
        if was_stashed:
            print("[!] Your pre-update local changes are safely stored in git stash.")
            print("    Review with: git stash list")
            print("    Restore when ready with: git stash pop")
        return 0
    except UpdateError as exc:
        print(f"[!] Update aborted: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
