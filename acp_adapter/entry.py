"""CLI entry point for the x19 ACP adapter.

Loads ``~/.x19/.env``, routes logging to stderr (stdout is reserved for ACP
JSON-RPC), and starts the ACP agent server.

Usage::

    python -m acp_adapter.entry   # or: x19 acp / x19-acp
"""

# IMPORTANT: x19_bootstrap must be the very first import — UTF-8 stdio
# on Windows.  No-op on POSIX.  See x19_bootstrap.py for full rationale.
try:
    import x19_bootstrap  # noqa: F401
except ModuleNotFoundError:
    # Partial ``x19 update`` (git-reset landed, ``uv pip install -e .`` did not):
    # UTF-8 stdio setup is skipped on Windows; POSIX is unaffected.
    pass
else:
    # Stop a ``utils/``/``proxy/``/``ui/`` package in the launch cwd from shadowing X19 modules.
    x19_bootstrap.harden_import_path()

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path
from x19_constants import get_x19_home


# Liveness-probe methods outside the ACP schema. The router correctly answers JSON-RPC -32601
# (clients treat that as "agent alive"), but the dispatching supervisor task also logs
# ``"Background task failed"`` with a traceback every probe. Keep the response; silence the noise.
_BENIGN_PROBE_METHODS = frozenset({"ping", "health", "healthcheck"})


class _BenignProbeMethodFilter(logging.Filter):
    """Suppress acp 'Background task failed' tracebacks caused by unknown liveness-probe methods
    (e.g. ``ping``); every other background-task error, incl. method_not_found for non-probe
    methods, stays visible."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.getMessage() != "Background task failed" or not record.exc_info:
            return True
        # Lazy import keeps this module importable without ``agent-client-protocol``.
        try:
            from acp.exceptions import RequestError
        except ImportError:
            return True
        exc = record.exc_info[1]
        if not isinstance(exc, RequestError) or getattr(exc, "code", None) != -32601:
            return True
        data = getattr(exc, "data", None)
        return not (isinstance(data, dict) and data.get("method") in _BENIGN_PROBE_METHODS)


def _setup_logging() -> None:
    """Route all logging to stderr so stdout stays clean for ACP stdio."""
    from agent.redact import RedactingFormatter

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(RedactingFormatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                                            datefmt="%Y-%m-%d %H:%M:%S"))
    handler.addFilter(_BenignProbeMethodFilter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    for noisy in ("httpx", "httpcore", "openai"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def _load_env() -> None:
    """Load .env from X19_HOME (default ``~/.x19``)."""
    from x19_cli.env_loader import load_x19_dotenv

    x19_home = get_x19_home()
    loaded = load_x19_dotenv(x19_home=x19_home)
    log = logging.getLogger(__name__)
    for env_file in loaded or ():
        log.info("Loaded env from %s", env_file)
    if not loaded:
        log.info("No .env found at %s, using system env", x19_home / ".env")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="x19-acp", description="Run X19 as an ACP stdio server.")
    parser.add_argument("--version", action="store_true", help="Print X19 version and exit")
    parser.add_argument("--check", action="store_true", help="Verify ACP dependencies and adapter imports, then exit")
    parser.add_argument("--setup", action="store_true",
                        help="Run interactive X19 provider/model setup for ACP terminal auth")
    parser.add_argument("--setup-browser", action="store_true",
                        help="Install agent-browser + Playwright Chromium into ~/.x19/node/ "
                             "for browser tool support. Idempotent.")
    parser.add_argument("--yes", "-y", action="store_true", dest="assume_yes",
                        help="Accept all prompts (currently used by --setup-browser to skip the "
                             "~400 MB Chromium download confirmation).")
    return parser.parse_args(argv)


def _print_version() -> None:
    from x19_cli import __version__ as x19_version

    print(x19_version)


def _run_check() -> None:
    import acp  # noqa: F401
    from acp_adapter.server import X19ACPAgent  # noqa: F401

    print("X19 ACP check OK")


def _run_setup() -> None:
    from x19_cli.main import main as x19_main

    old_argv = sys.argv[:]
    try:
        sys.argv = [old_argv[0] if old_argv else "x19", "model"]
        x19_main()
    finally:
        sys.argv = old_argv

    # Terminal auth is the first-run UX for registry installs, so offer the browser-tools
    # install here. Skip silently without a TTY.
    if not sys.stdin.isatty():
        return
    try:
        reply = input("\nInstall browser tools? Downloads agent-browser (npm) and "
                      "optionally Playwright Chromium (~400 MB). [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return
    if reply in {"y", "yes"}:
        _run_setup_browser(assume_yes=False)


_SETUP_BROWSER_STEPS = (
    ("node", "Node.js installation failed — cannot proceed with browser tools."),
    ("browser", "Browser tools installation failed."),
)


def _run_setup_browser(assume_yes: bool = False) -> int:
    """Bootstrap agent-browser + Chromium via dep_ensure -> install.{sh,ps1}
    --ensure (shared with the runtime lazy installer). Returns 0 on success, 1 on failure."""
    from x19_cli.dep_ensure import ensure_dependency

    try:
        for dep, failure_msg in _SETUP_BROWSER_STEPS:
            if not ensure_dependency(dep, interactive=not assume_yes):
                print(failure_msg, file=sys.stderr)
                return 1
        return 0
    except OSError as exc:
        print(f"Browser bootstrap failed: {exc}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> None:
    """Entry point: load env, configure logging, run the ACP agent."""
    args = _parse_args(argv)
    for flag, action in (("version", _print_version), ("check", _run_check), ("setup", _run_setup)):
        if getattr(args, flag):
            return action()
    if args.setup_browser:
        if rc := _run_setup_browser(assume_yes=args.assume_yes):
            sys.exit(rc)
        return

    _setup_logging()
    _load_env()

    logger = logging.getLogger(__name__)
    logger.info("Starting x19 ACP adapter")

    # Ensure the project root is on sys.path so ``from run_agent import AIAgent`` works
    project_root = str(Path(__file__).resolve().parent.parent)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    import acp
    from .server import X19ACPAgent

    # MCP discovery from config.yaml runs in a background daemon thread so the ACP server is
    # responsive immediately (blocking here cost 2-5 s); per-session MCP servers registered via
    # asyncio.to_thread are unaffected. Metadata-only hosts can opt out of the global startup.
    # Previously this blocked asyncio.run() for 2-5 s. (ACP also registers per-session MCP servers
    # dynamically via asyncio.to_thread inside the event loop; that path is unaffected.)  Moved from
    # model_tools.py module scope to avoid freezing the gateway's loop on lazy import (#16856).
    if os.environ.get("X19_ACP_SKIP_CONFIGURED_MCP", "").strip() != "1":
        try:
            from x19_cli.mcp_startup import start_background_mcp_discovery

            start_background_mcp_discovery(logger=logger, thread_name="acp-mcp-discovery")
        except Exception:
            logger.debug("MCP tool discovery failed at ACP startup", exc_info=True)

    agent = X19ACPAgent()
    try:
        asyncio.run(acp.run_agent(agent, use_unstable_protocol=True))
    except KeyboardInterrupt:
        logger.info("Shutting down (KeyboardInterrupt)")
    except Exception:
        logger.exception("ACP agent crashed")
        sys.exit(1)


if __name__ == "__main__":
    main()
