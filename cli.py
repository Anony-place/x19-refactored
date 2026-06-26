import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime
from typing import Optional, Dict, List, Any

from windows_bootstrap import apply_windows_utf8_bootstrap
apply_windows_utf8_bootstrap()

from constants import C, ICO, BANNER, PROVIDERS, PROVIDER_PRIORITY, _provider_has_key
from agent import X19
from providers import make_ai, is_bug_bounty_mode, is_ctf_mode, is_fast_mode
from tools import BrowserAutomation
from utils import validate_target
from config import CONFIG, CONFIG_FILE, load_config, save_config, set_data
from logging_utils import log, swallow as _swallow
from interactive import chat_loop, interactive

# Telegram is conditionally available — the class lives in the monolith and
# will be extracted to x19.telegram during a later refactor.
try:
    from telegram import TelegramBot
except ImportError:
    TelegramBot = None


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
        m = re.search(r'<longcat_arg_key>\s*(?:command|cmd|shell)\s*</longcat_arg_key>\s*<longcat_arg_value>\s*(.*?)\s*(?:</longcat_arg_value>|</longcat_tool_call>|<longcat_arg_key>|\Z)', block, re.DOTALL | re.IGNORECASE)
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
    "the", "a", "an", "my", "this", "that", "please", "now", "do", "run", "test", "pentest",
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
    cfg = load_config()
    provider_id = cfg.get("AI_PROVIDER", CONFIG.AI_PROVIDER)
    model = cfg.get("AI_MODEL", CONFIG.AI_MODEL or PROVIDERS.get(provider_id, {}).get("default_model", ""))

    if provider_id not in PROVIDERS:
        provider_id = ""

    if not provider_id:
        print(f"\n{C.BOLD}{C.Y}Select AI Provider:{C.N}")
        keys = sorted(PROVIDERS.keys())
        for i, pid in enumerate(keys, 1):
            info = PROVIDERS[pid]
            print(f"  {C.G}[{i}]{C.N} {info['name']:20} {info['desc']}")
        choice = input(f"\n{C.B}[?] Provider (1-{len(keys)}): {C.N}").strip()
        try:
            idx = int(choice) - 1
            provider_id = keys[idx]
        except (ValueError, IndexError):
            provider_id = "openrouter"
        save_config({"AI_PROVIDER": provider_id})
        print(f"{C.G}[+] Provider saved: {PROVIDERS[provider_id]['name']}{C.N}")

    info = PROVIDERS[provider_id]

    if info["needs_key"]:
        key = os.getenv(info["api_key_env"], "") or cfg.get(info["api_key_config"], "")
        if not key:
            print(f"{C.Y}[!] {info['name']} API key not found.{C.N}")
            key = input(f"{C.B}[?] {info['name']} API key: {C.N}").strip()
            if key:
                _save_key_for(provider_id, key)
                print(f"{C.G}[+] API key saved{C.N}")

    if not model:
        default = info["default_model"]
        print(f"{C.Y}[*] Default model: {default}{C.N}")
        custom = input(f"{C.B}[?] Model (press Enter for default): {C.N}").strip()
        model = custom or default
        save_config({"AI_MODEL": model})

    target = input(f"{C.B}[?] Target (IP or hostname): {C.N}").strip()
    while not target:
        target = input(f"{C.B}[?] Target required: {C.N}").strip()
    return target


# ===================================================================
# Start Telegram bot if token and users are configured
# ===================================================================
def _maybe_start_telegram(agent) -> Optional[Any]:
    has_token = os.getenv("TELEGRAM_BOT_TOKEN") or load_config().get("TELEGRAM_BOT_TOKEN")
    has_users = os.getenv("ALLOWED_TELEGRAM_USERS") or load_config().get("ALLOWED_TELEGRAM_USERS")
    if has_token and has_users and TelegramBot is not None:
        try:
            tg = TelegramBot(agent)
            t = threading.Thread(target=tg.run, daemon=True)
            t.start()
            print(f"{C.G}[+] Telegram bot active in background{C.N}")
            return tg
        except RuntimeError as e:
            print(f"{C.Y}[!] Telegram skipped: {e}{C.N}")
    return None


# ===================================================================
# Print AI provider chain banner
# ===================================================================
def _print_ai_chain_banner():
    """Print which providers X19 will try, in order. Helps user spot misconfig."""
    cfg = load_config()
    primary = cfg.get("AI_PROVIDER", CONFIG.AI_PROVIDER) or "openrouter"
    model = cfg.get("AI_MODEL") or PROVIDERS.get(primary, {}).get("default_model", "")
    has_groq = bool(os.getenv("GROQ_API_KEY") or cfg.get("GROQ_API_KEY"))
    has_or = bool(os.getenv("OPENROUTER_API_KEY") or cfg.get("OPENROUTER_API_KEY"))
    keys = []
    if has_groq:
        keys.append("groq")
    if has_or:
        keys.append("openrouter")
    chain = []
    # Primary provider first, then others in priority order
    if _provider_has_key(primary):
        chain.append(primary)
    for pid in PROVIDER_PRIORITY:
        if pid == "ollama" or pid == primary:
            continue
        if _provider_has_key(pid):
            chain.append(pid)
    if not chain:
        chain_str = f"{C.R}no AI provider keys configured{C.N}"
    else:
        chain_str = " -> ".join(f"{C.G}{p}{C.N}" for p in chain[:5])
        if len(chain) > 5:
            chain_str += f" -> {C.D}...({len(chain)-5} more){C.N}"
    print(f"{C.BOLD}AI chain:{C.N} {chain_str}")
    print(f"{C.D}  primary={primary}  model={model or '(provider default)'}{C.N}")
    if not has_groq:
        print(f"{C.Y}  Tip: free Llama 3.3 70B (no card) at https://console.groq.com/keys "
              f"-> x19 --setup-groq gsk_...{C.N}")
    has_cerebras = bool(os.getenv("CEREBRAS_API_KEY") or cfg.get("CEREBRAS_API_KEY"))
    if not has_cerebras:
        print(f"{C.Y}  Tip: free Cerebras inference (Llama 3.3 70B) at https://cloud.cerebras.ai/ "
              f"-> x19 --setup-cerebras csk-...{C.N}")
    has_hf = bool(os.getenv("HF_TOKEN") or cfg.get("HF_TOKEN"))
    if not has_hf:
        print(f"{C.Y}  Tip: free Hugging Face Inference API (Llama 3.1 8B) at https://huggingface.co/settings/tokens "
              f"-> export HF_TOKEN=hf_...{C.N}")


# ===================================================================
# Main entry point
# ===================================================================
def main():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(BANNER)

    import argparse
    parser = argparse.ArgumentParser(description="X19 - Autonomous AI Pentest Agent")
    parser.add_argument("--set-data", "-d", type=str, default="",
                        help="Pre-configure agent with JSON data. E.g. '{\"AI_PROVIDER\":\"openrouter\",\"OPENROUTER_API_KEY\":\"sk-...\",\"TARGET\":\"10.0.0.1\"}'")
    parser.add_argument("--target", "-t", type=str, default="",
                        help="Target to scan (auto-starts assessment)")
    parser.add_argument("--provider", "-p", type=str, default="",
                        help="AI provider (openrouter, openai, anthropic, nvidia, etc.)")
    parser.add_argument("--model", "-m", type=str, default="",
                        help="AI model name")
    parser.add_argument("--api-key", "-k", type=str, default="",
                        help="API key for the AI provider")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Minimal output")
    parser.add_argument("--interactive", "-i", action="store_true",
                        help="Force interactive console mode")
    parser.add_argument("--target-type", type=str, default="",
                        choices=["auto", "public_real_world", "authorized", "ctf", "lab"],
                        help="Target classification: public_real_world (recon only), authorized/ctf/lab (full attack)")
    parser.add_argument("--bug-bounty", "-b", action="store_true",
                        help="Hands-free bug bounty mode: parallel bootstrap, authorized scope, faster loop")
    parser.add_argument("--ctf", "-c", action="store_true",
                        help="CTF mode: aggressive exploitation, flag hunting, parallel recon, authorized scope")
    parser.add_argument("--fast", "-f", action="store_true",
                        help="Fast decisions: smaller prompt/context, skip extra LLM verify")
    parser.add_argument("--browser", type=str, default="", choices=["render", "forms", "screenshot"],
                        help="Run a headless-browser action and exit")
    parser.add_argument("--url", type=str, default="", help="URL for --browser")
    parser.add_argument("--setup-groq", type=str, default="",
                        help="One-shot: store GROQ_API_KEY + set AI_PROVIDER=groq + AI_MODEL=llama-3.3-70b-versatile, then exit. Use: x19 --setup-groq gsk_...")
    parser.add_argument("--setup-cerebras", type=str, default="",
                        help="One-shot: store CEREBRAS_API_KEY + set AI_PROVIDER=cerebras + AI_MODEL=llama-3.3-70b, then exit. Get free key at https://cloud.cerebras.ai/")
    args = parser.parse_args()

    if args.browser:
        res = getattr(BrowserAutomation(), args.browser)(args.url)
        if res.get("error"):
            print(res["error"])
        elif args.browser == "render":
            print(res.get("html", ""))
        else:
            print(json.dumps(res, indent=2))
        return

    # Apply --setup-groq: one-shot config for the free, fast Groq provider
    if args.setup_groq:
        key = args.setup_groq.strip()
        if not key.startswith("gsk_"):
            print(f"{C.R}[!] Groq API keys start with 'gsk_'. Got: {key[:8]}...{C.N}")
            print(f"{C.Y}    Get a free key (no card) at https://console.groq.com/keys{C.N}")
            sys.exit(1)
        set_data({
            "AI_PROVIDER": "groq",
            "AI_MODEL": "llama-3.3-70b-versatile",
            "GROQ_API_KEY": key,
        })
        print(f"{C.G}[+] Groq configured: provider=groq, model=llama-3.3-70b-versatile{C.N}")
        print(f"{C.G}[+] Key stored in $HOME/.x19/config.json. X19 will try Groq first,{C.N}")
        print(f"{C.G}    then auto-fallback to other free models if Groq is down.{C.N}")
        sys.exit(0)

    # Apply --setup-cerebras: one-shot config for the free, fast Cerebras inference
    if args.setup_cerebras:
        key = args.setup_cerebras.strip()
        if not key:
            print(f"{C.R}[!] Empty key. Get one at https://cloud.cerebras.ai/{C.N}")
            sys.exit(1)
        set_data({
            "AI_PROVIDER": "cerebras",
            "AI_MODEL": "llama-3.3-70b",
            "CEREBRAS_API_KEY": key,
        })
        print(f"{C.G}[+] Cerebras configured: provider=cerebras, model=llama-3.3-70b{C.N}")
        print(f"{C.G}[+] Free tier ~1M tokens/day, very fast inference.{C.N}")
        sys.exit(0)

    # Apply --set-data first
    if args.set_data:
        try:
            data = json.loads(args.set_data)
            set_data(data)
            print(f"{C.G}[+] Data set: {len(data)} keys{C.N}")
        except json.JSONDecodeError as e:
            print(f"{C.R}[!] Invalid --set-data JSON: {e}{C.N}")
            sys.exit(1)

    # Apply individual args
    cli_data = {}
    if args.provider:
        if args.provider not in PROVIDERS:
            valid = [p for p in PROVIDERS if p != "ollama"]
            print(f"{C.R}[!] Unknown provider '{args.provider}'{C.N}")
            print(f"{C.Y}    Valid providers: {', '.join(valid)}{C.N}")
            sys.exit(1)
        cli_data["AI_PROVIDER"] = args.provider
    if args.model:
        cli_data["AI_MODEL"] = args.model
    if args.api_key:
        provider_id = args.provider or load_config().get("AI_PROVIDER", CONFIG.AI_PROVIDER)
        if provider_id in PROVIDERS:
            cli_data[PROVIDERS[provider_id]["api_key_env"]] = args.api_key
    if cli_data:
        set_data(cli_data)

    if args.target_type:
        cli_data["TARGET_TYPE"] = args.target_type
        set_data({"TARGET_TYPE": args.target_type})

    # Print AI provider chain banner so user sees which models will be tried
    _print_ai_chain_banner()

    if args.target:
        set_data({"TARGET": args.target})

    if args.bug_bounty:
        set_data({
            "BUG_BOUNTY_MODE": "1",
            "FAST_MODE": "1",
            "TARGET_TYPE": args.target_type or "authorized",
            "AUTO_BOOTSTRAP": "1",
            "PARALLEL_PLAN": "1",
        })

    if args.ctf:
        set_data({
            "CTF_MODE": "1",
            "FAST_MODE": "1",
            "TARGET_TYPE": args.target_type or "ctf",
            "AUTO_BOOTSTRAP": "1",
            "PARALLEL_PLAN": "1",
        })

    if args.fast:
        set_data({"FAST_MODE": "1", "PARALLEL_PLAN": "1"})

    print(f"{ICO.GEAR} Config: {CONFIG_FILE}{C.N}")
    print(f"{ICO.GEAR} Workspace: {CONFIG.WORKSPACE}{C.N}")

    # Determine target
    target = args.target or os.getenv("X19_TARGET") or ""

    # First-run setup wizard: probe for any configured API key; if none found, walk the user through it.
    cfg = load_config()
    any_key = any(
        os.getenv(info["api_key_env"]) or cfg.get(info["api_key_config"], "")
        for pid, info in PROVIDERS.items() if info["needs_key"]
    )
    explicit_provider = cfg.get("AI_PROVIDER", "")
    ollama_available = bool(shutil.which("ollama"))

    if not any_key and not explicit_provider and not ollama_available:
        print(f"\n{C.BOLD}{C.Y}[!] No AI provider configured.{C.N}")
        print(f"{C.Y}    X19 needs at least one API key to work.{C.N}")
        print(f"{C.Y}    Let's set one up quickly.{C.N}\n")

        keys = sorted([p for p in PROVIDERS if PROVIDERS[p]["needs_key"] and p != "ollama"],
                      key=lambda p: PROVIDERS[p]["name"])
        print(f"{C.BOLD}Available Providers:{C.N}")
        for i, pid in enumerate(keys, 1):
            info = PROVIDERS[pid]
            tag = f"{C.G}[FREE]{C.N}" if "free" in info.get("desc","").lower() else ""
            key_hint = f" ({info['api_key_env']})"
            print(f"  {C.G}[{i}]{C.N} {info['name']:20} {info['desc'][:50]} {tag}")
        print(f"  {C.G}[0]{C.N} Skip (I'll configure later)")

        try:
            choice = input(f"\n{C.B}[?] Select provider (0-{len(keys)}): {C.N}").strip()
            idx = int(choice) - 1
            if idx >= 0 and idx < len(keys):
                pid = keys[idx]
                info = PROVIDERS[pid]
                print(f"\n{C.Y}[*] Selected: {info['name']}{C.N}")
                print(f"{C.Y}[*] Get your API key from the provider's website{C.N}")
                api_key = input(f"{C.B}[?] {info['name']} API key: {C.N}").strip()
                if api_key:
                    _save_key_for(pid, api_key)
                    set_data({"AI_PROVIDER": pid, "AI_MODEL": info["default_model"]})
                    print(f"{C.G}[+] {info['name']} configured!{C.N}")
        except (ValueError, IndexError, EOFError):
            print(f"{C.Y}[*] Skipping setup — run with --setup-groq or --setup-cerebras later.{C.N}")

    print(f"{ICO.BOLT} Initializing AI provider...{C.N}", flush=True)
    ai = make_ai()
    print(f"{ICO.OK} AI: {ai.name()}{C.N}", flush=True)
    print(f"{ICO.GEAR} Loading agent...{C.N}", flush=True)

    # If fully configured via CLI, just run
    if target:
        agent = X19(ai=ai)
        print(f"{ICO.OK} Agent ready{C.N}", flush=True)
        _maybe_start_telegram(agent)
        if is_bug_bounty_mode():
            print(f"{ICO.BOLT} Bug bounty mode — hands-free autonomous run on: {target}{C.N}")
        elif is_ctf_mode():
            print(f"{ICO.FLAG} CTF mode — flag hunting on: {target}{C.N}")
        else:
            print(f"{ICO.BOLT} Auto-running assessment on: {target}{C.N}")
        agent.autonomous_loop(target)
        if agent.session.data.get("status") == "failed":
            print(f"\n{ICO.FAIL} Assessment failed — see status above. {len(agent.findings())} findings.{C.N}")
        else:
            print(f"\n{ICO.OK} Assessment complete. {len(agent.findings())} findings.{C.N}")
        print(f"{ICO.NODE} Report: {agent.session.report()[:1000]}{C.N}")
        return

    # Start Telegram if configured
    agent = X19(ai=ai)
    print(f"{ICO.OK} Agent ready{C.N}", flush=True)
    _maybe_start_telegram(agent)

    # --interactive flag goes to old fixed-command console
    if args.interactive:
        interactive(agent)
        print(f"{ICO.NODE} Sessions: {CONFIG.SESSIONS_DIR}{C.N}")
        return

    # Default: AI chat loop
    chat_loop(agent)
    print(f"{ICO.NODE} Sessions: {CONFIG.SESSIONS_DIR}{C.N}")
