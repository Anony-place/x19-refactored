"""Early runtime compatibility fixes installed before cli/agent imports."""
from __future__ import annotations

import builtins
import os
import shutil
import sys


def install_runtime_fixes() -> None:
    # mission.py historically calls this helper without importing it. Expose
    # the canonical implementation through builtins before cli imports agent.
    try:
        from memory import is_bug_bounty_mode
        builtins.is_bug_bounty_mode = is_bug_bounty_mode
    except Exception:
        pass

    # ProxyManager's mitmproxy detector references sys.executable but the
    # network module did not import sys. Patch the detector at the boundary so
    # venv/pip-installed mitmproxy binaries are still detected.
    try:
        from network import ProxyManager

        def detect_mitmproxy(self) -> bool:
            names = ("mitmdump", "mitmproxy", "mitmweb")
            if any(shutil.which(name) for name in names):
                return True
            bindir = os.path.dirname(sys.executable)
            exts = (".exe", ".cmd", "") if os.name == "nt" else ("",)
            return any(
                os.path.exists(os.path.join(bindir, name + ext))
                for name in names for ext in exts
            )

        ProxyManager._detect_mitmproxy = detect_mitmproxy

        # When Burp + mitmproxy are both running, X19's capture proxy is the
        # mitmproxy listener (8081), not Burp's upstream listener (8080).
        def proxy_url(self) -> str:
            if self.mitm_proc is not None:
                return "http://127.0.0.1:8081"
            return "http://127.0.0.1:8080"

        ProxyManager.proxy_url = proxy_url
    except Exception:
        pass
