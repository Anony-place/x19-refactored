"""X19 command-line interface.

Design goals (4.0.0):

* **Subcommand CLI** — ``x19 <command>``, the shape every serious tool has.
  Legacy flag-only invocations (``x19 -t host``) are still accepted and routed
  to ``x19 run``.
* **Terminal-native, application-grade UI** — every screen is rendered by
  :mod:`ui`. There is no web server any more; the dashboard, findings triage,
  provider management, diagnostics and report export all live in the terminal.
* **Two output contracts** — styled output for humans, ``--json`` for machines.
* **Cheap commands stay cheap** — ``--version``, ``--help``, ``doctor``,
  ``config``, ``providers`` and ``report`` never trigger the first-run AI
  wizard. Only commands that actually need a model do.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from typing import Any, Dict, List, Optional

from windows_bootstrap import apply_windows_utf8_bootstrap
apply_windows_utf8_bootstrap()

from constants import PROVIDERS, PROVIDER_PRIORITY, _provider_has_key
from config import CONFIG, CONFIG_FILE, load_config, save_config, set_data
from logging_utils import swallow as _swallow
from version import __version__, version_info

# Telegram is conditionally available — the class lives in the monolith and
# will be extracted to x19.telegram during a later refactor.
try:
    from telegram import TelegramBot
except ImportError:
    TelegramBot = None


COMMANDS = (
    "run", "dash", "chat", "report", "findings", "sessions",
    "providers", "config", "doctor", "tools", "debug", "setup",
    "upgrade", "version", "completion",
)

#: Commands that need a working AI provider before they can do anything.
PROVIDER_COMMANDS = ("run", "chat")


# ===================================================================
# Helper: save an API key to both config and environment
# ===================================================================
def _save_key_for(provider_id: str, key: str):
    info = PROVIDERS[provider_id]
    cfg_key = info["api_key_config"]
    if cfg_key:
        save_config({cfg_key: key})
    env = info["api_key_env"]
    if env:
        os.environ[env] = key
        if os.name == "nt":
            try:
                subprocess.run(["setx", env, key], capture_output=True, timeout=5)
            except Exception as e:
                _swallow(e)


# ===================================================================
# Extract shell commands from <longcat_tool_call> blocks
# ===================================================================
def _extract_longcat_commands(response: str) -> List[str]:
    """Extract shell commands from <longcat_tool_call> exec blocks (tool-call format some models emit instead of EXEC:)."""
    cmds = []
    for block in re.findall(r'<longcat_tool_call>(.*?)(?:</longcat_tool_call>|\Z)', response, re.DOTALL | re.IGNORECASE):
        m = re.search(r'<longcat_arg_key>\s*(?:command|cmd|shell)\s*</longcat_arg_key>\s*<longcat_arg_value>\s*(.*?)\s*(?:</longcat_arg_value>|</longcat_tool_call>|</longcat_arg_key>|\Z)', block, re.DOTALL | re.IGNORECASE)
        if m and m.group(1).strip():
            cmds.append(m.group(1).strip())
    return cmds


# ===================================================================
# Extract shell commands from EXEC: directives
# ===================================================================
def _extract_exec_commands(response: str) -> List[str]:
    """Extract single-line shell commands from EXEC: directives (never multiline blobs)."""
    cmds = []
    for raw_line in response.splitlines():
        line = raw_line.strip()
        if not line.upper().startswith("EXEC:"):
            continue
        cmd = line.split(":", 1)[1].strip()
        if not cmd:
            continue
        if re.match(r"^(RESULT|\[\*|You:|User:)", cmd, re.I):
            continue
        cmds.append(cmd)
    cmds.extend(_extract_longcat_commands(response))
    return cmds


# ===================================================================
# Data for _parse_target_from_user_line
# ===================================================================
_PREPOSITIONS = {"on", "in", "for", "against", "with", "from", "into", "at", "to", "of"}
_NON_TARGETS = _PREPOSITIONS | {
    "the", "a", "an", "my", "this", "that", "please", "now", "do", "run", "pentest",
    "scan", "target", "engage", "hack", "assess", "enumerate", "device", "android", "ios",
    "mobile", "app", "apk", "adb", "bug", "bounty", "ctf", "lab",
}
_HOST_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|^[a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,}$")


# ===================================================================
# Parse a pentest request from a user line
# ===================================================================
def _parse_target_from_user_line(line: str) -> Optional[dict]:
    """Parse a pentest request. Returns {intent,target,target_type} or None.
    Never returns a preposition or keyword (on/in/for/test/device/android/...) as a target."""
    parts = line.strip().split()
    if not parts:
        return None
    lower = line.lower()
    is_pentest = parts[0].lower() in ("target", "scan", "pentest", "engage", "hack") or \
        any(re.search(r'\b' + re.escape(w) + r'\b', lower) for w in ("pentest", "scan", "assess", "enumerate", "hack"))
    if not is_pentest:
        return None
    # Engagement type hint
    tt = None
    if "--authorized" in lower or "authorized" in lower or "bug bounty" in lower or "bounty" in lower:
        tt = "authorized"
    elif " ctf" in lower:
        tt = "ctf"
    elif " lab" in lower:
        tt = "lab"
    mobile = any(w in lower for w in ("android", "apk", "adb", "ios", "mobile"))
    # Find a real host/IP — skip flags, prepositions and keywords (req 1,2,5)
    host = None
    for tok in parts:
        tok = tok.strip().rstrip(".,")
        if not tok or tok.startswith("-") or tok.lower() in _NON_TARGETS:
            continue
        if _HOST_RE.match(tok):
            host = tok
            break
    if mobile:
        host = host or _android_device_id(line)
        intent = "android_pentest"
    elif not host:
        return None
    elif re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host):
        intent = "network_pentest"
    else:
        intent = "web_pentest" if host else "pentest"
    return {"intent": intent, "target": host, "target_type": tt}


# ===================================================================
# Extract Android device identifier
# ===================================================================
def _android_device_id(line: str) -> Optional[str]:
    """Extract an Android device identifier: device IP[:port], adb serial, APK path, or package name."""
    m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b', line)   # device IP[:port]
    if m:
        return m.group(0)
    m = re.search(r'\S+\.apk\b', line)                            # APK path
    if m:
        return m.group(0)
    m = re.search(r'\b[a-z][\w]*\.[\w]+\.[\w.]+\b', line, re.I)    # package name com.x.y
    if m and m.group(0).count('.') >= 2 and not m.group(0).lower().endswith(
            ('.com', '.net', '.org', '.io', '.dev', '.app')):
        return m.group(0)
    return None


# ===================================================================
# Interactive setup: prompt user for provider, API key, model, target
# ===================================================================
def _interactive_setup() -> str:
    """Prompt user for provider, API key, model, and target — all in one terminal flow."""
    from rich.prompt import Prompt

    from ui.console import get_console, ok, warn

    console = get_console()
    cfg = load_config()
    provider_id = cfg.get("AI_PROVIDER", CONFIG.AI_PROVIDER)
    model = cfg.get("AI_MODEL", CONFIG.AI_MODEL or PROVIDERS.get(provider_id, {}).get("default_model", ""))

    if provider_id not in PROVIDERS:
        provider_id = ""

    if not provider_id:
        from ui.screens import providers_screen

        console.print(providers_screen(PROVIDERS))
        choice = Prompt.ask("provider id", console=console, default="groq").strip()
        provider_id = choice if choice in PROVIDERS else "openrouter"
        save_config({"AI_PROVIDER": provider_id})
        ok(f"provider saved: {PROVIDERS[provider_id]['name']}")

    info = PROVIDERS[provider_id]

    if info["needs_key"]:
        key = os.getenv(info["api_key_env"], "") or cfg.get(info["api_key_config"], "")
        if not key:
            import getpass

            warn(f"{info['name']} API key not found")
            key = getpass.getpass(f"{info['name']} API key: ").strip()
            if key:
                _save_key_for(provider_id, key)
                ok("API key saved")

    if not model:
        default = info["default_model"]
        custom = Prompt.ask("model", console=console, default=default).strip()
        model = custom or default
        save_config({"AI_MODEL": model})

    target = Prompt.ask("target (IP or hostname)", console=console).strip()
    while not target:
        target = Prompt.ask("target required", console=console).strip()
    return target


# ===================================================================
# Start Telegram bot if token and users are configured
# ===================================================================
def _maybe_start_telegram(agent) -> Optional[Any]:
    from ui.console import info, warn

    has_token = os.getenv("TELEGRAM_BOT_TOKEN") or load_config().get("TELEGRAM_BOT_TOKEN")
    has_users = os.getenv("ALLOWED_TELEGRAM_USERS") or load_config().get("ALLOWED_TELEGRAM_USERS")
    if has_token and has_users and TelegramBot is not None:
        try:
            tg = TelegramBot(agent)
            t = threading.Thread(target=tg.run, daemon=True)
            t.start()
            info("Telegram bot active in background")
            return tg
        except RuntimeError as e:
            warn(f"Telegram skipped: {e}")
    return None


# ===================================================================
# AI provider chain summary
# ===================================================================
def provider_chain_summary() -> Dict[str, Any]:
    """Which providers X19 will try, in order — as data, not print statements."""
    cfg = load_config()
    primary = cfg.get("AI_PROVIDER", CONFIG.AI_PROVIDER) or "openrouter"
    model = cfg.get("AI_MODEL") or PROVIDERS.get(primary, {}).get("default_model", "")
    chain = [primary] if _provider_has_key(primary) else []
    for pid in PROVIDER_PRIORITY:
        if pid == "ollama" or pid == primary:
            continue
        if _provider_has_key(pid):
            chain.append(pid)
    return {
        "primary": primary,
        "model": model,
        "chain": chain,
        "configured": bool(chain),
        "ollama": bool(shutil.which("ollama")),
    }


def _print_ai_chain_banner():
    """Print which providers X19 will try, in order. Helps user spot misconfig."""
    from ui.console import get_console, info, warn

    summary = provider_chain_summary()
    console = get_console()
    if summary["chain"]:
        chain_text = " [app.dim]→[/] ".join(f"[app.ok]{p}[/]" for p in summary["chain"][:5])
        if len(summary["chain"]) > 5:
            chain_text += f" [app.dim]→ …(+{len(summary['chain']) - 5})[/]"
    else:
        chain_text = "[app.err]no AI provider keys configured[/]"
    info(f"AI chain: {chain_text}")
    console.print(
        f"  [app.dim]primary={summary['primary']}  model={summary['model'] or '(provider default)'}[/]"
    )
    if not (os.getenv("GROQ_API_KEY") or load_config().get("GROQ_API_KEY")):
        warn("free Llama 3.3 70B (no card): https://console.groq.com/keys → x19 setup")
    if not (os.getenv("HF_TOKEN") or load_config().get("HF_TOKEN")):
        warn("free Hugging Face inference: https://huggingface.co/settings/tokens → export HF_TOKEN=hf_…")


# ===================================================================
# Parser
# ===================================================================
def _common_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="machine-readable JSON on stdout")
    common.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    common.add_argument("--plain", action="store_true", help="no live TUI, plain scrolling output")
    common.add_argument("-q", "--quiet", action="store_true", help="only print results")
    common.add_argument("-v", "--verbose", action="store_true", help="extra diagnostics")
    return common


def build_parser() -> argparse.ArgumentParser:
    common = _common_parser()
    parser = argparse.ArgumentParser(
        prog="x19",
        add_help=False,
        parents=[common],
        description="X19 — autonomous AI security assessment platform (terminal application)",
    )
    parser.add_argument("-h", "--help", action="store_true", help="show this help and exit")
    parser.add_argument("-V", "--version", action="store_true", help="show version and exit")

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # -- run -------------------------------------------------------------
    p = sub.add_parser("run", parents=[common], help="run an autonomous assessment against a target")
    p.add_argument("-t", "--target", type=str, default="", help="target host, IP, URL or CIDR")
    p.add_argument("--target-type", type=str, default="",
                   choices=["auto", "public_real_world", "authorized", "ctf", "lab"],
                   help="engagement classification")
    p.add_argument("-b", "--bug-bounty", action="store_true", help="hands-free authorized bug bounty mode")
    p.add_argument("-c", "--ctf", action="store_true", help="CTF mode: aggressive, flag hunting")
    p.add_argument("-f", "--fast", action="store_true", help="fast decisions: smaller prompt/context")
    p.add_argument("-p", "--provider", type=str, default="", help="AI provider id")
    p.add_argument("-m", "--model", type=str, default="", help="AI model name")
    p.add_argument("-k", "--api-key", type=str, default="", help="API key for the provider")
    p.add_argument("-d", "--set-data", type=str, default="", help="pre-configure with a JSON object")
    p.add_argument("--max-iterations", type=int, default=0, help="stop after N decision iterations")
    p.add_argument("--swarm", action="store_true", help="use the parallel swarm pipeline + live dashboard")
    p.add_argument("-i", "--interactive", action="store_true", help="legacy fixed-command console")
    p.add_argument("--browser", type=str, default="", choices=["render", "forms", "screenshot"],
                   help="run one headless-browser action and exit")
    p.add_argument("--url", type=str, default="", help="URL for --browser")
    p.add_argument("--setup-groq", type=str, default="", help="store a Groq key, set provider, exit")
    p.add_argument("--setup-cerebras", type=str, default="", help="store a Cerebras key, set provider, exit")

    # -- dash ------------------------------------------------------------
    p = sub.add_parser("dash", parents=[common], help="live swarm mission control (full screen)")
    p.add_argument("-t", "--target", type=str, default="", help="target to assess")
    p.add_argument("--refresh", type=float, default=0.5, help="redraw interval in seconds")
    p.add_argument("--once", action="store_true", help="render a single frame and exit")
    p.add_argument("--no-tui", action="store_true", help="stream frames instead of full-screen")
    p.add_argument("--timeout", type=float, default=0, help="stop after N seconds")
    p.add_argument("--no-start", action="store_true", help="attach without launching the pipeline")

    # -- chat ------------------------------------------------------------
    p = sub.add_parser("chat", parents=[common], help="interactive AI assistant (default command)")
    p.add_argument("--system", type=str, default="", help="override the system prompt")

    # -- report ----------------------------------------------------------
    p = sub.add_parser("report", parents=[common], help="export an assessment report")
    p.add_argument("--format", type=str, default="markdown", choices=["markdown", "html", "json", "text"],
                   help="output format")
    p.add_argument("--session", type=str, default="", help="session id (default: latest)")
    p.add_argument("--out", type=str, default="", help="write to a file instead of stdout")

    # -- findings --------------------------------------------------------
    p = sub.add_parser("findings", parents=[common], help="list recorded findings")
    p.add_argument("--session", type=str, default="", help="session id (default: latest)")
    p.add_argument("--severity", type=str, default="", help="filter by severity")

    # -- sessions --------------------------------------------------------
    p = sub.add_parser("sessions", parents=[common], help="inspect stored sessions")
    p.add_argument("action", nargs="?", default="list", choices=["list", "show"], help="what to do")
    p.add_argument("session", nargs="?", default="", help="session id for 'show'")

    # -- providers -------------------------------------------------------
    p = sub.add_parser("providers", parents=[common], help="manage AI providers")
    p.add_argument("--use", type=str, default="", help="set the primary provider")
    p.add_argument("--model", type=str, default="", help="set the default model")
    p.add_argument("--test", action="store_true", help="round-trip the configured provider")
    p.add_argument("--reveal", action="store_true", help="show configured keys in full")

    # -- config ----------------------------------------------------------
    p = sub.add_parser("config", parents=[common], help="show or change configuration")
    p.add_argument("action", nargs="?", default="show", choices=["show", "get", "set", "unset", "path", "reset"])
    p.add_argument("args", nargs="*", help="KEY [VALUE]")
    p.add_argument("--reveal", action="store_true", help="do not mask secrets")

    # -- doctor ----------------------------------------------------------
    p = sub.add_parser("doctor", parents=[common], help="health check and self diagnostics")
    p.add_argument("--network", action="store_true", help="also probe outbound network")

    # -- tools -----------------------------------------------------------
    p = sub.add_parser("tools", parents=[common], help="toolchain availability")
    p.add_argument("--missing", action="store_true", help="only list binaries that are absent")

    # -- debug -----------------------------------------------------------
    p = sub.add_parser("debug", parents=[common], help="source-code diagnostics and auto-fix")
    p.add_argument("action", nargs="?", default="scan", choices=["scan", "fix", "check", "stats"],
                   help="scan (read-only), fix, check or stats")

    # -- setup -----------------------------------------------------------
    p = sub.add_parser("setup", parents=[common], help="first-run AI provider configuration")
    p.add_argument("--force", action="store_true", help="re-run even when already configured")

    # -- upgrade ---------------------------------------------------------
    sub.add_parser("upgrade", parents=[common], help="autonomous self-upgrade pipeline")

    # -- version ---------------------------------------------------------
    sub.add_parser("version", parents=[common], help="show version and environment details")

    # -- completion ------------------------------------------------------
    p = sub.add_parser("completion", parents=[common], help="print a shell completion script")
    p.add_argument("shell", nargs="?", default="bash", choices=["bash", "zsh", "fish"],
                   help="shell flavour (default: bash)")

    return parser


# ===================================================================
# Argument normalisation (legacy flag-first invocations)
# ===================================================================
_GLOBAL_FIRST = {"-h", "--help", "-V", "--version"}


def normalize_argv(argv: List[str]) -> List[str]:
    """Route legacy invocations to the matching subcommand.

    ``x19 -t host``            → ``x19 run -t host``
    ``x19 --json report``      → ``x19 report --json``
    ``x19 --upgrade``          → ``x19 upgrade``
    """
    if not argv:
        return []
    if argv[0] in _GLOBAL_FIRST:
        return argv
    if argv[0] in COMMANDS:
        return argv
    if argv[0] == "--upgrade":
        return ["upgrade"] + argv[1:]
    for index, token in enumerate(argv):
        if token in COMMANDS:
            return [token] + argv[index + 1:] + argv[:index]
    return ["run"] + argv


# ===================================================================
# Shared bootstrap
# ===================================================================
def _apply_runtime_config(args: argparse.Namespace) -> None:
    """Translate run flags into the global config the agent reads."""
    from ui.console import ok

    set_data_raw = getattr(args, "set_data", "")
    if set_data_raw:
        try:
            data = json.loads(set_data_raw)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"invalid --set-data JSON: {exc}")
        set_data(data)
        ok(f"data set: {len(data)} keys")

    cli_data: Dict[str, Any] = {}
    provider = getattr(args, "provider", "")
    if provider:
        if provider not in PROVIDERS:
            valid = [p for p in PROVIDERS if p != "ollama"]
            raise SystemExit(f"unknown provider '{provider}' — valid: {', '.join(valid)}")
        cli_data["AI_PROVIDER"] = provider
    model = getattr(args, "model", "")
    if model:
        cli_data["AI_MODEL"] = model
    api_key = getattr(args, "api_key", "")
    if api_key:
        provider_id = provider or load_config().get("AI_PROVIDER", CONFIG.AI_PROVIDER)
        if provider_id in PROVIDERS:
            cli_data[PROVIDERS[provider_id]["api_key_env"]] = api_key
    if cli_data:
        set_data(cli_data)

    target_type = getattr(args, "target_type", "")
    if target_type:
        set_data({"TARGET_TYPE": target_type})
    if getattr(args, "bug_bounty", False):
        set_data({
            "BUG_BOUNTY_MODE": "1", "FAST_MODE": "1",
            "TARGET_TYPE": target_type or "authorized",
            "AUTO_BOOTSTRAP": "1", "PARALLEL_PLAN": "1",
        })
    if getattr(args, "ctf", False):
        set_data({
            "CTF_MODE": "1", "FAST_MODE": "1",
            "TARGET_TYPE": target_type or "ctf",
            "AUTO_BOOTSTRAP": "1", "PARALLEL_PLAN": "1",
        })
    if getattr(args, "fast", False):
        set_data({"FAST_MODE": "1", "PARALLEL_PLAN": "1"})
    if getattr(args, "max_iterations", 0):
        set_data({"MAX_ITERATIONS": str(args.max_iterations)})


def _make_agent():
    from agent import X19
    from providers import make_ai
    from ui.console import ok, step

    step("initialising AI provider")
    ai = make_ai()
    ok(f"AI: {ai.name()}")
    step("loading agent")
    agent = X19(ai=ai)
    ok("agent ready")
    return agent, ai


# ===================================================================
# Commands
# ===================================================================
def cmd_version(args: argparse.Namespace) -> int:
    from ui.console import emit_json, get_console
    from ui.screens import env_screen

    data = version_info()
    if getattr(args, "json", False):
        emit_json(data)
        return 0
    get_console().print(env_screen(data))
    get_console().print(
        "[app.dim]x19 --help for commands · x19 doctor for a health check · "
        "x19 report --format html to export[/]"
    )
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    import cli_support
    from ui.console import emit_json, get_console
    from ui.screens import doctor_screen

    result = cli_support.run_diagnostics(check_network=bool(getattr(args, "network", False)))
    if getattr(args, "json", False):
        payload = dict(result)
        payload["toolchain"] = {k: v for k, v in result["toolchain"].items() if k != "rows"}
        emit_json(payload)
        return 0 if result["score"] >= 60 else 1
    get_console().print(doctor_screen(result["checks"], score=result["score"]))
    failed = [c for c in result["checks"] if c["status"] == "fail"]
    if failed:
        get_console().print(f"[app.err]✖ {len(failed)} check(s) failed[/]")
        return 1
    get_console().print("[app.ok]✔ healthy[/]")
    return 0


def cmd_tools(args: argparse.Namespace) -> int:
    import cli_support
    from ui.console import emit_json, get_console
    from ui.screens import tools_screen

    rows = cli_support.toolchain_rows()
    if getattr(args, "missing", False):
        rows = [row for row in rows if not row["available"]]
    if getattr(args, "json", False):
        emit_json(rows)
        return 0
    get_console().print(tools_screen(rows))
    installed = sum(1 for row in rows if row["available"])
    get_console().print(f"[app.dim]{installed}/{len(rows)} available[/]")
    return 0


def cmd_providers(args: argparse.Namespace) -> int:
    from provider_setup import configured_chain
    from ui.console import emit_json, get_console, ok, warn
    from ui.screens import providers_screen

    if getattr(args, "use", ""):
        pid = args.use
        if pid not in PROVIDERS:
            warn(f"unknown provider '{pid}'")
            return 1
        set_data({"AI_PROVIDER": pid})
        if args.model:
            set_data({"AI_MODEL": args.model})
        ok(f"primary provider set to {pid}")

    if getattr(args, "model", "") and not getattr(args, "use", ""):
        set_data({"AI_MODEL": args.model})
        ok(f"model set to {args.model}")

    chain = configured_chain()
    summary = provider_chain_summary()

    if getattr(args, "test", False):
        from providers import make_ai

        ai = make_ai()
        reply = ai.chat("Reply with the single word: ready.", "ping")
        if reply:
            ok(f"{ai.name()} responded: {reply.strip()[:80]}")
        else:
            warn(f"{ai.name()} returned an empty response")

    if getattr(args, "json", False):
        emit_json({
            "providers": {pid: {"name": i["name"], "needs_key": i["needs_key"],
                                "default_model": i.get("default_model", ""),
                                "configured": _provider_has_key(pid)}
                          for pid, i in PROVIDERS.items()},
            "chain": chain,
            "resolved": summary,
        })
        return 0

    cfg = load_config()
    providers = {pid: dict(info, configured=_provider_has_key(pid)) for pid, info in PROVIDERS.items()}
    get_console().print(providers_screen(
        providers, current=cfg.get("AI_PROVIDER", ""), chain=chain, priority=PROVIDER_PRIORITY
    ))
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    from ui.console import emit_json, get_console, ok, warn
    from ui.screens import config_screen

    action = getattr(args, "action", "show")
    extra = list(getattr(args, "args", []) or [])
    config = load_config()

    if action == "path":
        if getattr(args, "json", False):
            emit_json({"path": str(CONFIG_FILE)})
        else:
            get_console().print(str(CONFIG_FILE))
        return 0

    if action == "reset":
        try:
            CONFIG_FILE.unlink()
        except FileNotFoundError:
            pass
        ok(f"removed {CONFIG_FILE}")
        return 0

    if action == "unset":
        if not extra:
            warn("usage: x19 config unset KEY")
            return 1
        remaining = {k: v for k, v in config.items() if k.upper() != extra[0].upper()}
        CONFIG_FILE.write_text(json.dumps(remaining, indent=2), encoding="utf-8")
        ok(f"unset {extra[0]}")
        return 0

    if action == "get":
        if not extra:
            warn("usage: x19 config get KEY")
            return 1
        value = config.get(extra[0].upper(), config.get(extra[0], ""))
        if getattr(args, "json", False):
            emit_json({extra[0]: value})
        else:
            get_console().print(str(value))
        return 0

    if action == "set":
        updates: Dict[str, str] = {}
        for token in extra:
            if "=" in token:
                key, value = token.split("=", 1)
                updates[key.strip().upper()] = value.strip()
            else:
                warn(f"expected KEY=VALUE, got '{token}'")
        if updates:
            set_data(updates)
            ok("saved " + ", ".join(updates))
            config = load_config()

    if getattr(args, "json", False):
        masked = dict(config)
        if not getattr(args, "reveal", False):
            from ui.screens import is_secret_key, mask_secret

            masked = {k: (mask_secret(v) if is_secret_key(k) and v else v) for k, v in masked.items()}
        emit_json(masked)
        return 0

    get_console().print(config_screen(config, path=str(CONFIG_FILE), reveal=bool(getattr(args, "reveal", False))))
    return 0


def _resolve_session(args: argparse.Namespace) -> Optional[Dict[str, Any]]:
    import cli_support

    session_id = getattr(args, "session", "")
    if session_id:
        return cli_support.load_session(session_id)
    return cli_support.latest_session()


def cmd_sessions(args: argparse.Namespace) -> int:
    import cli_support
    from ui.console import emit_json, get_console, warn
    from ui.screens import session_detail_screen, sessions_screen

    action = getattr(args, "action", "list")
    if action == "show":
        session_id = getattr(args, "session", "") or ""
        data = cli_support.load_session(session_id) if session_id else cli_support.latest_session()
        if not data:
            warn(f"no such session: {session_id or '(none recorded)'}")
            return 1
        if getattr(args, "json", False):
            emit_json(data)
        else:
            get_console().print(session_detail_screen(data, data.get("session_id", "")))
        return 0

    rows = cli_support.list_sessions()
    if getattr(args, "json", False):
        emit_json(rows)
        return 0
    get_console().print(sessions_screen(rows))
    get_console().print(f"[app.dim]directory: {CONFIG.SESSIONS_DIR}[/]")
    return 0


def cmd_findings(args: argparse.Namespace) -> int:
    from ui.console import emit_json, get_console, warn
    from ui.screens import findings_screen

    data = _resolve_session(args)
    if not data:
        warn("no session recorded — run: x19 run -t <target>")
        return 1
    findings = data.get("findings") or []
    severity = getattr(args, "severity", "").lower()
    if severity:
        findings = [f for f in findings if str(f.get("severity", "")).lower() == severity]
    if getattr(args, "json", False):
        emit_json({"session": data.get("session_id"), "target": data.get("target"), "findings": findings})
        return 0
    get_console().print(findings_screen(findings, target=data.get("target", "")))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    import cli_support
    from ui.console import emit_json, get_console, warn

    data = _resolve_session(args)
    if not data:
        warn("no session recorded — run: x19 run -t <target>")
        return 1

    fmt = getattr(args, "format", "markdown")
    findings = cli_support.session_findings(data)
    target = data.get("target", "unknown")

    if fmt == "text":
        from storage import Session

        session = Session()
        session.id = data.get("session_id")
        session.data = data
        content = session.report()
    else:
        from reporting.report_generator import SecurityReportGenerator

        generator = SecurityReportGenerator(
            target=target,
            findings=findings,
            metadata={
                "session_id": data.get("session_id", ""),
                "started": data.get("started", ""),
                "iterations": data.get("iterations", 0),
                "tool": f"X19 {__version__}",
            },
        )
        content = {
            "markdown": generator.generate_markdown,
            "html": generator.generate_html,
            "json": generator.generate_json,
        }[fmt]()

    out = getattr(args, "out", "")
    if out:
        from pathlib import Path

        Path(out).write_text(content, encoding="utf-8")
        get_console().print(f"[app.ok]✔ report written to {out}[/]")
        return 0
    if fmt == "json" or getattr(args, "json", False):
        if fmt == "json":
            sys.stdout.write(content + "\n")
        else:
            emit_json(json.loads(content) if fmt == "json" else data)
        return 0
    sys.stdout.write(content + "\n")
    return 0


def cmd_dash(args: argparse.Namespace) -> int:
    from brain.coordinator import SwarmCoordinator
    from ui.console import get_console, is_plain_mode, warn
    from ui.dashboard import MissionDashboard

    target = getattr(args, "target", "") or os.getenv("X19_TARGET", "")
    if not target:
        warn("target required — x19 dash -t <host>")
        return 1

    coordinator = SwarmCoordinator()
    dashboard = MissionDashboard(
        coordinator,
        version=__version__,
        refresh=float(getattr(args, "refresh", 0.5) or 0.5),
        console=get_console(),
    )
    dashboard.run(
        target=target,
        once=bool(getattr(args, "once", False)),
        headless=True if (getattr(args, "no_tui", False) or is_plain_mode()) else None,
        start=not getattr(args, "no_start", False),
        timeout=float(getattr(args, "timeout", 0) or 0) or None,
    )
    ran = not getattr(args, "no_start", False) and not getattr(args, "once", False)
    if ran and not getattr(args, "json", False):
        get_console().print(dashboard.report())
    return 0


def cmd_debug(args: argparse.Namespace) -> int:
    """Delegate to the standalone source diagnostics tool."""
    import x19debugger

    debugger = x19debugger.X19Debugger()
    action = getattr(args, "action", "scan")
    {
        "scan": x19debugger.cmd_scan,
        "fix": x19debugger.cmd_fix,
        "check": x19debugger.cmd_check,
        "stats": x19debugger.cmd_stats,
    }[action](debugger)
    return 0


_COMPLETIONS = {
    "bash": """# X19 bash completion — eval "$(x19 completion bash)"
_x19_complete() {{
    local cur cmds
    COMPREPLY=()
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    cmds="{commands}"
    if [ "${{COMP_CWORD}}" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "${{cmds}}" -- "${{cur}}") )
    fi
    return 0
}}
complete -F _x19_complete x19
""",
    "zsh": """# X19 zsh completion — eval "$(x19 completion zsh)"
_x19() {{
    local -a commands
    commands=({zsh_commands})
    if (( CURRENT == 2 )); then
        _describe 'command' commands
    fi
}}
compdef _x19 x19
""",
    "fish": """# X19 fish completion — x19 completion fish | source
{fish_commands}
""",
}


def cmd_completion(args: argparse.Namespace) -> int:
    shell = getattr(args, "shell", "bash")
    names = list(COMMANDS)
    if shell == "bash":
        script = _COMPLETIONS["bash"].format(commands=" ".join(names))
    elif shell == "zsh":
        script = _COMPLETIONS["zsh"].format(
            zsh_commands=" ".join(f"'{name}:x19 {name}'" for name in names)
        )
    else:
        script = _COMPLETIONS["fish"].format(
            fish_commands="\n".join(
                f"complete -c x19 -f -n '__fish_use_subcommand' -a '{name}'" for name in names
            )
        )
    sys.stdout.write(script)
    return 0


def cmd_setup(args: argparse.Namespace) -> int:
    from provider_setup import setup_if_needed
    from ui.console import ok, warn

    if not setup_if_needed(force=bool(getattr(args, "force", False))):
        warn("setup cancelled — no working provider saved")
        return 1
    ok("provider chain saved")
    return 0


def cmd_upgrade(args: argparse.Namespace) -> int:
    from x19upgrader import X19Upgrader

    return 0 if X19Upgrader().run_pipeline() else 1


def cmd_chat(args: argparse.Namespace) -> int:
    import ui.app as app_module
    from ui.app import ConsoleApp
    from ui.console import banner

    if not _ensure_provider():
        return 1

    agent, ai = _make_agent()
    _maybe_start_telegram(agent)
    banner(__version__, subtitle=f"interactive console · {ai.name()}")
    system = getattr(args, "system", "")
    if system:
        app_module.SYSTEM_PROMPT = system
    return ConsoleApp(agent, version=__version__, ai=ai).run()


def cmd_run(args: argparse.Namespace) -> int:
    from providers import is_bug_bounty_mode, is_ctf_mode
    from ui.console import banner, emit_json, get_console, info, ok, warn
    from ui import widgets

    # one-shot browser action (no agent required)
    if getattr(args, "browser", ""):
        from tools import BrowserAutomation

        result = getattr(BrowserAutomation(), args.browser)(getattr(args, "url", ""))
        if getattr(args, "json", False):
            emit_json(result)
        elif result.get("error"):
            warn(result["error"])
        elif args.browser == "render":
            get_console().print(result.get("html", ""))
        else:
            get_console().print_json(json.dumps(result, default=str))
        return 1 if result.get("error") else 0

    # one-shot provider shortcuts
    if getattr(args, "setup_groq", ""):
        key = args.setup_groq.strip()
        if not key.startswith("gsk_"):
            warn(f"Groq keys start with 'gsk_' — got {key[:8]}…")
            get_console().print("  [app.dim]free key: https://console.groq.com/keys[/]")
            return 1
        set_data({"AI_PROVIDER": "groq", "AI_MODEL": "llama-3.3-70b-versatile", "GROQ_API_KEY": key})
        ok("Groq configured — provider=groq model=llama-3.3-70b-versatile")
        return 0
    if getattr(args, "setup_cerebras", ""):
        key = args.setup_cerebras.strip()
        if not key:
            warn("empty key — get one at https://cloud.cerebras.ai/")
            return 1
        set_data({"AI_PROVIDER": "cerebras", "AI_MODEL": "llama-3.3-70b", "CEREBRAS_API_KEY": key})
        ok("Cerebras configured — provider=cerebras model=llama-3.3-70b")
        return 0

    _apply_runtime_config(args)
    _print_ai_chain_banner()

    target = getattr(args, "target", "") or os.getenv("X19_TARGET", "")
    if getattr(args, "target", ""):
        set_data({"TARGET": args.target})

    # swarm pipeline → the live dashboard owns the run
    if getattr(args, "swarm", False):
        if not target:
            warn("target required — x19 run -t <host> --swarm")
            return 1
        return cmd_dash(args)

    if not _ensure_provider():
        return 1

    if not getattr(args, "quiet", False):
        banner(__version__, subtitle="autonomous assessment")

    agent, ai = _make_agent()
    _maybe_start_telegram(agent)

    if not target:
        from ui.app import ConsoleApp

        app = ConsoleApp(agent, version=__version__, ai=ai)
        return app.run()

    if getattr(args, "interactive", False):
        from interactive import interactive

        interactive(agent)
        get_console().print(f"[app.dim]sessions: {CONFIG.SESSIONS_DIR}[/]")
        return 0

    if is_bug_bounty_mode():
        info(f"bug bounty mode — hands-free autonomous run on {target}")
    elif is_ctf_mode():
        info(f"CTF mode — flag hunting on {target}")
    else:
        info(f"auto-running assessment on {target}")

    agent.autonomous_loop(target)
    findings = agent.findings()
    failed = agent.session.data.get("status") == "failed"
    if getattr(args, "json", False):
        emit_json({
            "target": target,
            "session": agent.session.id,
            "status": agent.session.data.get("status"),
            "iterations": agent.session.data.get("iterations", 0),
            "findings": agent.session.data.get("findings", []),
        })
        return 1 if failed else 0

    get_console().print(widgets.panel(
        "assessment complete" if not failed else "assessment failed",
        widgets.kv_table([
            ("target", target),
            ("session", agent.session.id or "—"),
            ("iterations", agent.session.data.get("iterations", 0)),
            ("findings", len(findings)),
        ]),
        border_style="bright_green" if not failed else "bright_red",
    ))
    get_console().print(f"[app.dim]sessions: {CONFIG.SESSIONS_DIR} · report: x19 report[/]")
    return 1 if failed else 0


def _ensure_provider() -> bool:
    from cli_support import ensure_provider_configured, resolve_provider
    from ui.console import info, warn

    try:
        configured = ensure_provider_configured()
    except (EOFError, KeyboardInterrupt):
        configured = False
    except Exception as exc:
        warn(f"provider setup failed: {exc}")
        return False
    if not configured:
        warn("no AI provider configured — run: x19 setup")
        return False
    resolved = resolve_provider()
    if resolved:
        info(f"AI provider: [bold]{resolved}[/]")
    return True


HANDLERS = {
    "run": cmd_run,
    "dash": cmd_dash,
    "chat": cmd_chat,
    "report": cmd_report,
    "findings": cmd_findings,
    "sessions": cmd_sessions,
    "providers": cmd_providers,
    "config": cmd_config,
    "doctor": cmd_doctor,
    "tools": cmd_tools,
    "debug": cmd_debug,
    "setup": cmd_setup,
    "upgrade": cmd_upgrade,
    "version": cmd_version,
    "completion": cmd_completion,
}


# ===================================================================
# Help screen
# ===================================================================
HELP_COMMANDS = [
    {"name": "run", "help": "autonomous assessment against a target (-t, --bug-bounty, --ctf, --fast)", "group": "assessment"},
    {"name": "dash", "help": "full-screen live swarm mission control", "group": "assessment"},
    {"name": "findings", "help": "list recorded findings by severity", "group": "assessment"},
    {"name": "report", "help": "export markdown / html / json / text reports", "group": "assessment"},
    {"name": "chat", "help": "interactive AI assistant (default when no command is given)", "group": "interactive"},
    {"name": "sessions", "help": "list or inspect stored assessment sessions", "group": "interactive"},
    {"name": "providers", "help": "list providers, set the primary, test connectivity", "group": "configuration"},
    {"name": "config", "help": "show, get, set, unset or reset configuration", "group": "configuration"},
    {"name": "setup", "help": "first-run AI provider wizard", "group": "configuration"},
    {"name": "doctor", "help": "health check, dependencies, toolchain, self diagnostics", "group": "operations"},
    {"name": "tools", "help": "toolchain availability", "group": "operations"},
    {"name": "debug", "help": "source-code diagnostics: scan / fix / check / stats", "group": "operations"},
    {"name": "completion", "help": "print a bash / zsh / fish completion script", "group": "operations"},
    {"name": "upgrade", "help": "autonomous self-upgrade pipeline", "group": "operations"},
    {"name": "version", "help": "version and environment details", "group": "operations"},
]


def print_help(parser: argparse.ArgumentParser) -> None:
    from ui.console import banner, get_console
    from ui.screens import help_screen

    banner(__version__, subtitle="terminal application · no web ui")
    get_console().print(help_screen(HELP_COMMANDS, version=__version__))
    get_console().print(
        "[app.dim]global flags:[/] --json  --no-color  --plain  -q/--quiet  -v/--verbose  "
        "-V/--version\n"
        "[app.dim]examples:[/]   x19 run -t scanme.nmap.org --bug-bounty\n"
        "           x19 dash -t 10.0.0.5\n"
        "           x19 report --format html --out report.html\n"
        "           x19 doctor --json | jq .score\n"
    )


# ===================================================================
# Main entry point
# ===================================================================
def main(argv: Optional[List[str]] = None) -> int:
    from ui.console import get_console, init_console

    argv = normalize_argv(list(sys.argv[1:] if argv is None else argv))
    parser = build_parser()
    args = parser.parse_args(argv)

    init_console(
        no_color=bool(getattr(args, "no_color", False)),
        plain=bool(getattr(args, "plain", False)),
        json_mode=bool(getattr(args, "json", False)),
    )

    if getattr(args, "help", False) and not getattr(args, "command", None):
        print_help(parser)
        return 0
    if getattr(args, "version", False):
        return cmd_version(args)

    command = getattr(args, "command", None)
    if not command:
        command = "chat"
        args.command = command

    handler = HANDLERS.get(command)
    if handler is None:
        parser.print_usage()
        return 2

    try:
        return int(handler(args) or 0)
    except KeyboardInterrupt:
        get_console().print("\n[app.warn]![/] interrupted")
        return 130
    except SystemExit as exc:
        code = exc.code
        if isinstance(code, str):
            get_console().print(f"[app.err]✖ {code}[/]")
            return 1
        return int(code or 0)
