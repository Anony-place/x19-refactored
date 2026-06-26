import os
import sys
import re
import json
import time
import subprocess
from typing import Optional, List, Dict, TYPE_CHECKING

from constants import C, ICO
from config import CONFIG, SCRIPTS_DIR, PAYLOADS_DIR, WORDLISTS_DIR, save_config
from providers import make_ai
from memory import _memory_disabled
from context_compressor import ContextCompressor


def _get_clipboard() -> Optional[str]:
    """Read clipboard content — works on Windows (PowerShell) and Linux (xclip)."""
    try:
        if os.name == "nt":
            r = subprocess.run(["powershell", "-Command", "Get-Clipboard"],
                               capture_output=True, text=False, timeout=5)
            so = (r.stdout or b"").decode("utf-8", errors="replace")
            if r.returncode == 0 and so.strip():
                return so.strip()
        else:
            for cmd in (["xclip", "-o", "-selection", "clipboard"],
                        ["xsel", "-o", "-b"],
                        ["wl-paste"]):
                try:
                    r = subprocess.run(cmd, capture_output=True, text=False, timeout=5)
                    so2 = (r.stdout or b"").decode("utf-8", errors="replace")
                    if r.returncode == 0 and so2.strip():
                        return so2.strip()
                except FileNotFoundError:
                    continue
    except Exception:
        pass
    return None

if TYPE_CHECKING:
    from agent import X19


def interactive(agent: "X19"):
    print(f"\n{C.BOLD}{C.B}  X19  interactive console — fixed commands{C.N}")
    print(f"{C.Y}  engage <target>, provider, model, status, findings, report, shell, help, exit{C.N}")
    while True:
        try:
            line = input(f"{C.B}x19{C.N}@{C.B}{agent.target or '?'}{C.N} {C.M}$ {C.N}").strip()
            if not line:
                continue
            parts = line.split()
            cmd = parts[0].lower()
            args = parts[1:]

            if cmd == "exit":
                break
            elif cmd == "engage":
                t = args[0] if args else input("Target: ").strip()
                if t:
                    agent.autonomous_loop(t)
                else:
                    print(f"{C.R}[!] Target required{C.N}")
            elif cmd == "provider":
                new = make_ai("__menu__")
                agent.ai = new
                print(f"{C.G}[+] Switched to: {new.name()}{C.N}")
            elif cmd == "model":
                mdl = " ".join(args) if args else input("Model name: ").strip()
                if mdl:
                    save_config({"AI_MODEL": mdl})
                    CONFIG.AI_MODEL = mdl
                    print(f"{C.G}[+] Model set: {mdl}. Reconnect with 'provider' to apply.{C.N}")
                else:
                    print(f"{C.Y}[!] Usage: model <name> (e.g. model gpt-4o){C.N}")
            elif cmd == "status":
                print(f"AI: {agent.ai.name()}")
                print(f"Target: {agent.target or 'N/A'}")
                print(f"Session: {agent.session.id or 'N/A'}")
                print(f"Running: {agent.running}")
                print(f"Iterations: {agent.session.data.get('iterations', 0)}")
                print(agent.session.findings_summary())
            elif cmd == "findings":
                for i, f in enumerate(agent.findings(), 1):
                    print(f"{i:3}. [{f.severity.upper():8}] {f.title}")
                    print(f"     {f.description[:200]}")
            elif cmd == "report":
                print(agent.session.report())
            elif cmd == "shell":
                print(f"{C.Y}[*] System shell (exit to return){C.N}")
                try:
                    subprocess.run(["powershell"] if os.name == "nt" else ["/bin/bash"])
                except Exception as e:
                    print(f"{C.R}{e}{C.N}")
            elif cmd == "test":
                print(f"{C.Y}[*] Testing AI backend: {agent.ai.name()}{C.N}")
                r = agent.ai.chat("Say hello in one word.", "Respond now.")
                if r:
                    print(f"{C.G}[+] Response: {r[:200]}{C.N}")
                else:
                    print(f"{C.R}[!] Empty response — check API key, model name, and network{C.N}")
            elif cmd == ":clip":
                clip = _get_clipboard()
                if clip:
                    print(f"{C.G}[+] Clipboard: {len(clip)} chars{C.N}")
                    print(clip[:2000])
                else:
                    print(f"{C.Y}[!] Clipboard empty/inaccessible{C.N}")
            elif cmd == "help":
                print("engage <target>  - Start autonomous assessment")
                print("provider         - Switch AI provider")
                print("model <name>     - Set model name")
                print(":paste           - Multi-line paste mode (:end to finish)")
                print(":clip            - Read directly from clipboard (no paste issues)")
                print(":read <file>     - Load text from file")
                print("status           - Current assessment status")
                print("findings         - List findings & vulnerabilities")
                print("report           - Generate assessment report")
                print("shell            - System shell")
                print("test             - Test AI connection")
                print("exit             - Quit")
            else:
                r = agent.exec.run(line)
                if getattr(r, "stdout", None):
                    print(r.stdout)
        except KeyboardInterrupt:
            print()
        except EOFError:
            break


def chat_loop(agent: "X19"):
    print(f"\n{C.BOLD}{C.B}  X19  interactive assistant — chat, code, assess{C.N}")
    print(f"{ICO.NODE} AI: {agent.ai.name()}{C.N}\n")

    try:
        if getattr(agent, "memory", None) and agent.memory.ready:
            print(
                f"{ICO.INFO} Memory active ({agent.memory.count('techniques')} techniques, {agent.memory.count('lessons')} lessons){C.N}"
            )
        elif not _memory_disabled():
            print(f"{ICO.GEAR} Vector memory loading in background (ChromaDB)...{C.N}", flush=True)
        if getattr(agent, "learner", None):
            agent.learner.start()
            print(f"{ICO.MORE} Background learner active (daily DuckDuckGo research){C.N}")
    except Exception:
        pass

    print(f"{ICO.OK} Ready — type a message or /help{C.N}", flush=True)
    print(f"{C.D}Tip: use ':paste' for multi-line input, ':read <file>' to load from file{C.N}")

    history: List[Dict] = []
    compressor = ContextCompressor()
    while True:
        try:
            sys.stdout.flush()
            sys.stderr.flush()
            line = input(f"{C.B}x19{C.N} {C.D}({agent.ai.name()[:20]}){C.N} {C.M}>{C.N} ").strip()
            if not line:
                continue

            cmd = line.split()[0].lower()
            if cmd in ("/exit", "exit"):
                print(f"{C.Y}[!] Bye{C.N}")
                break

            if cmd == "/help":
                print(f"{C.Y}Commands:{C.N}")
                print("  target <host>     - Start full autonomous pentest")
                print("  scan|pentest <h>  - Alias for target")
                print("  :paste            - Paste multi-line input (end with :end or . on its own line)")
                print("  :clip             - Read directly from clipboard (no paste issues)")
                print("  :read <file>      - Load text from file as input")
                print("  /status           - Session & findings status")
                print("  /findings         - List all findings")
                print("  /report           - Show assessment report")
                print("  /memory           - Show vector memory (techniques, lessons, CVEs)")
                print("  /learn [now]      - Background learner status or force research cycle")
                print("  /provider         - Switch AI provider")
                print("  /model <name>     - Set AI model")
                print("  /shell            - System shell")
                print("  /test             - Test AI connection")
                print("  /clear            - Clear chat history")
                print("  /datasets         - Show available scripts, payloads, wordlists")
                print("  /proxy            - Start/stop/status Burp Suite + mitmproxy")
                print("  /help, /exit      - This or quit")
                continue

            if cmd == ":paste":
                print(f"{C.Y}[*] Paste mode — paste your text, then type :end or '.' alone on a line to finish{C.N}")
                paste_lines = []
                while True:
                    try:
                        pl = input()
                        if pl.strip() in (":end", "."):
                            break
                        paste_lines.append(pl)
                    except (EOFError, KeyboardInterrupt):
                        break
                if paste_lines:
                    line = "\n".join(paste_lines)
                    print(f"{C.G}[+] Received {len(paste_lines)} lines, {len(line)} chars{C.N}")
                else:
                    print(f"{C.Y}[!] Empty paste, cancelled{C.N}")
                    continue

            if cmd == ":read":
                fname = " ".join(line.split()[1:]).strip()
                if not fname:
                    print(f"{C.Y}[!] Usage: :read <filepath>{C.N}")
                    continue
                try:
                    with open(fname, "r", encoding="utf-8", errors="replace") as fh:
                        line = fh.read()
                    print(f"{C.G}[+] Loaded {len(line)} chars from {fname}{C.N}")
                except Exception as e:
                    print(f"{C.R}[!] Failed to read {fname}: {e}{C.N}")
                    continue

            if cmd == ":clip":
                try:
                    clip = _get_clipboard()
                    if clip:
                        line = clip
                        print(f"{C.G}[+] Read {len(line)} chars from clipboard{C.N}")
                    else:
                        print(f"{C.Y}[!] Clipboard empty or inaccessible{C.N}")
                        continue
                except Exception as e:
                    print(f"{C.R}[!] Clipboard failed: {e}{C.N}")
                    continue

            if cmd == "/status":
                print(f"  AI:    {agent.ai.name()}")
                print(f"  Target:{getattr(agent, 'target', None) or 'N/A'}")
                print(f"  Ses:   {agent.session.id or 'N/A'}")
                print(f"  Run:   {getattr(agent, 'running', False)}")
                print(f"  Iters: {agent.session.data.get('iterations', 0)}")
                print(f"  {agent.session.findings_summary()}")
                continue

            if cmd == "/findings":
                any_found = False
                for i, f in enumerate(agent.findings(), 1):
                    any_found = True
                    print(f"  {i:3}. [{f.severity.upper():8}] {f.title}")
                    print(f"       {f.description[:200]}")
                if not any_found:
                    print(f"  {C.Y}[!] No findings yet{C.N}")
                continue

            if cmd == "/report":
                print(agent.session.report())
                continue

            if cmd == "/clear":
                history.clear()
                print(f"{C.G}[+] Chat history cleared{C.N}")
                continue

            if cmd == "/datasets":
                print(f"{C.BOLD}{C.Y}Datasets:{C.N}")
                for d, label in [(SCRIPTS_DIR, "Scripts"), (PAYLOADS_DIR, "Payloads"), (WORDLISTS_DIR, "Wordlists")]:
                    try:
                        files = list(d.rglob("*")) if d.exists() else []
                    except Exception:
                        files = []
                    print(f"  {C.G}{label}{C.N} ({len(files)} files):")
                    for f in sorted(files)[:2000]:
                        try:
                            rel = f.relative_to(d.parent.parent)
                        except Exception:
                            rel = f.name
                        size = len(f.read_bytes()) if getattr(f, "is_file", lambda: False)() else 0
                        print(f"    {C.B}{str(rel):50}{C.N} {size:>8} bytes")
                try:
                    from storage import DataManager
                    dataset_files = DataManager.list_datasets()
                    if dataset_files:
                        print(f"  {C.G}Local knowledge datasets{C.N} ({len(dataset_files)} files):")
                        for f in dataset_files[:2000]:
                            try:
                                rel = f.relative_to(DataManager.DATASETS_DIR.parent)
                            except Exception:
                                rel = f.name
                            size = len(f.read_bytes()) if getattr(f, "is_file", lambda: False)() else 0
                            print(f"    {C.B}{str(rel):50}{C.N} {size:>8} bytes")
                        print(f"  {C.D}These datasets are indexed into memory when the learner starts.{C.N}")
                except Exception:
                    pass
                continue

            if cmd in ("/proxy",):
                try:
                    state = agent.toggle_proxy()
                    print(state if isinstance(state, str) else f"{ICO.INFO} proxy toggled{C.N}")
                except Exception:
                    pass
                continue

            if cmd == "/memory":
                mem = getattr(agent, "memory", None)
                if not mem:
                    print(f"{C.Y}[!] No memory system available{C.N}")
                    continue
                if not mem.ready:
                    print(f"{C.Y}[!] Memory not ready (ChromaDB loading in background){C.N}")
                    continue
                print(mem.summary())
                try:
                    valid = mem.technique_validity()
                    print(f"  Technique validity: {valid['valid']}/{valid['total']} valid ({valid['valid_pct']}%)")
                except Exception:
                    pass
                try:
                    cves = mem.get_all("cves", limit=5)
                    if cves:
                        print(f"{C.C}Recent CVEs:{C.N}")
                        for e in cves:
                            meta = e.get("metadata", {}) or {}
                            snippet = e.get("text", "")[:120]
                            print(f"  [{meta.get('severity','?')}] {meta.get('date','')} — {snippet}")
                except Exception:
                    pass
                continue

            if cmd == "/learn":
                learner = getattr(agent, "learner", None)
                if not learner:
                    print(f"{C.Y}[!] No background learner available{C.N}")
                    continue
                rest = " ".join(line.split()[1:]).strip().lower()
                if rest == "now":
                    print(f"{C.D}[*] Forcing research cycle...{C.N}", flush=True)
                    count = learner.learn_now()
                    if count:
                        print(f"{C.G}[+] Learned {count} new techniques/CVEs{C.N}")
                    else:
                        print(f"{C.Y}[!] Nothing new learned{C.N}")
                else:
                    stats = getattr(learner, "_stats", {})
                    running = getattr(learner, "running", False)
                    print(f"  Learner: {'running' if running else 'stopped'}")
                    print(f"  Research cycles: {stats.get('cycles', 0)}")
                    print(f"  Articles/CVEs stored: {stats.get('articles', 0)}")
                    try:
                        last_file = getattr(learner, "_last_file", None)
                        last = last_file.read_text().strip() if last_file and last_file.exists() else "never"
                        print(f"  Last cycle: {last}")
                    except Exception:
                        pass
                    print(f"  Use '{C.B}/learn now{C.N}' to force a research cycle")
                continue

            if cmd == "/provider":
                new = make_ai("__menu__")
                agent.ai = new
                print(f"{C.G}[+] Switched to: {new.name()}{C.N}")
                continue

            if cmd == "/model":
                mdl = " ".join(line.split()[1:]).strip()
                if mdl:
                    save_config({"AI_MODEL": mdl})
                    CONFIG.AI_MODEL = mdl
                    agent.ai = make_ai()
                    print(f"{C.G}[+] Model set: {mdl} ({agent.ai.name()}){C.N}")
                else:
                    print(f"{C.Y}[!] Usage: /model <name>{C.N}")
                continue

            from cli import _parse_target_from_user_line
            parsed = _parse_target_from_user_line(line)
            if parsed and parsed.get("target"):
                if line.split()[0].lower() in ("target", "scan", "pentest", "engage", "hack") or parsed["intent"]:
                    agent.autonomous_loop(parsed["target"])
                    continue

            print(f"{ICO.GEAR} {C.D}thinking...{C.N}")
            system = ("You are X19, an autonomous AI pentest agent. "
                       "Your capabilities: port scanning (nmap), web enumeration (whatweb, curl, gobuster, ffuf), "
                       "CVE scanning (nuclei, whatweb, searchsploit), exploitation (metasploit, custom exploits), "
                       "subdomain recon (subfinder, assetfinder), DNS enumeration (dig, nslookup, host), "
                       "directory busting, service fingerprinting, and vulnerability assessment.\n\n"
                       "When asked about X19's capabilities: explain it is a real AI-driven pentesting tool that scans "
                       "targets, finds vulnerabilities, and attempts exploitation — not a simulation. "
                       "It runs actual nmap/nuclei/curl commands against targets.\n\n"
                       "How to use: tell the user to run 'target <host>' or 'scan <host>' to start an autonomous assessment, "
                       "or 'python run.py <target>' from command line.\n\n"
                       "Respond conversationally, concisely, and technically. Be honest if unsure. "
                       "If the user asks about a specific target, suggest running the target command.")
            ctx_parts = []
            for msg in history:
                role = msg.get("role", "user")
                content = msg.get("content", "")
                ctx_parts.append(f"{role.upper()}: {content[:2000]}")
            ctx = "\n".join(ctx_parts)
            ctx += f"\nUSER: {line}"
            response = agent.ai.chat(system, ctx)
            if not response:
                print(f"{C.R}[!] AI returned empty response{C.N}")
                continue
            history.append({"role": "user", "content": line})
            history.append({"role": "assistant", "content": response})
            # Auto-compress history when it grows beyond threshold
            if len(history) > 24:
                compressed = compressor.compress_messages(history)
                if len(compressed) < len(history):
                    print(f"{C.D}[Compressor] {len(history)}->{len(compressed)} messages{C.N}")
                    history = compressed
            display = re.sub(r'^\s*\{.*"thinking":\s*"', '', response, flags=re.DOTALL)
            if display != response:
                display = re.sub(r'".*"completed":\s*(?:false|true)\s*\}', '', display, flags=re.DOTALL)
                display = display.strip().strip('", ')
            else:
                display = response
            display = re.sub(r'^EXEC:.*$', '', display, flags=re.MULTILINE)
            display = re.sub(r'^PENTEST:.*$', '', display, flags=re.MULTILINE)
            display = re.sub(r'<longcat_tool_call>.*?</longcat_tool_call>', '', display, flags=re.DOTALL | re.IGNORECASE)
            display = re.sub(r'</?longcat_\w+>', '', display)
            display = display.strip()
            if display:
                print(f"{C.G}{display}{C.N}")
            exec_cmds = re.findall(r'^EXEC:\s*(.*)', response, re.MULTILINE)
            for cmd_to_run in exec_cmds[:2]:
                print(f"{C.Y}[*] Executing: {cmd_to_run[:200]}{C.N}")
                try:
                    r = agent.exec.run(cmd_to_run)
                    if getattr(r, "text", None):
                        print(f"{C.W}{r.text[:2000]}{C.N}")
                except Exception as e:
                    print(f"{C.R}[!] {e}{C.N}")
        except KeyboardInterrupt:
            print()
        except EOFError:
            break
