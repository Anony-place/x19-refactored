from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from datetime import datetime
from typing import Optional, Dict, List, Any, TYPE_CHECKING

import requests

from constants import C, ICO, BANNER, PROVIDERS, PROVIDER_PRIORITY, _provider_has_key
from utils import _parse_ints
from config import CONFIG, load_config, save_config, CONFIG_FILE
from logging_utils import log

if TYPE_CHECKING:
    from agent import X19


class TelegramBot:
    def __init__(self, agent: X19):
        self.agent = agent
        self.token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        if not self.token:
            cfg = load_config()
            self.token = cfg.get("TELEGRAM_BOT_TOKEN", "")
        if not self.token:
            print(f"{C.Y}[!] TELEGRAM_BOT_TOKEN not found. Enter it once — it will be saved permanently.{C.N}")
            self.token = input(f"{C.B}[?] Telegram Bot Token: {C.N}").strip()
            if not self.token:
                raise RuntimeError("TELEGRAM_BOT_TOKEN required for Telegram mode")
            save_config({"TELEGRAM_BOT_TOKEN": self.token})
            print(f"{C.G}[+] Saved to {CONFIG_FILE}{C.N}")
        self.allowed = _parse_ints(os.getenv("ALLOWED_TELEGRAM_USERS", ""))
        if not self.allowed:
            cfg = load_config()
            raw = cfg.get("ALLOWED_TELEGRAM_USERS", "")
            if raw:
                self.allowed = _parse_ints(raw)
        if not self.allowed:
            # Skip Telegram if allowed users not configured — avoids prompt every time
            print(f"{C.Y}[!] ALLOWED_TELEGRAM_USERS not set. Telegram disabled.{C.N}")
            print(f"{C.Y}    Set it via: set ALLOWED_TELEGRAM_USERS your_id{C.N}")
            self.token = ""  # disable telegram
            self.allowed = []
        self.offset = 0

    def _call(self, method: str, data: Dict) -> Dict:
        r = requests.post(f"https://api.telegram.org/bot{self.token}/{method}", json=data, timeout=30)
        r.raise_for_status()
        return r.json()

    def _updates(self) -> List[Dict]:
        d = self._call("getUpdates", {"timeout": CONFIG.TELEGRAM_LONGPOLL_TIMEOUT_SEC, "allowed_updates": ["message"], "offset": self.offset})
        return d.get("result", []) if d.get("ok") else []

    def _send(self, chat: int, text: str):
        self._call("sendMessage", {"chat_id": chat, "text": (text or "OK")[:CONFIG.TELEGRAM_MAX_MESSAGE_LEN]})

    def _auth(self, uid: int) -> bool:
        return uid in self.allowed

    def run(self):
        print(f"{C.G}[+] Telegram active ({len(self.allowed)} authorized users){C.N}")
        while True:
            try:
                for upd in self._updates():
                    msg = upd.get("message", {})
                    chat = msg.get("chat", {}).get("id")
                    uid = msg.get("from", {}).get("id")
                    text = msg.get("text", "")
                    uid_upd = upd.get("update_id")
                    if isinstance(uid_upd, int):
                        self.offset = max(self.offset, uid_upd + 1)
                    if not chat or not uid:
                        continue
                    if not self._auth(int(uid)):
                        log(f"UNAUTHORIZED tg uid={uid}")
                        continue
                    parts = text.strip().split()
                    if not parts:
                        continue
                    cmd = parts[0].split("@")[0]
                    args = parts[1:]

                    if cmd == "/scan":
                        t = args[0] if args else ""
                        if not t:
                            self._send(chat, "Usage: /scan <target>")
                            continue
                        if self.agent.running:
                            self._send(chat, "Already running. /stop first.")
                            continue
                        def _scan(tt=t, cc=chat):
                            try:
                                self._send(cc, f"Scanning {tt}...")
                                self.agent.autonomous_loop(tt)
                                self._send(cc, f"Done. {len(self.agent.findings())} findings.")
                            except Exception as e:
                                self._send(cc, f"Scan failed: {e}")
                            finally:
                                self.agent.running = False
                        threading.Thread(target=_scan, daemon=True).start()

                    elif cmd == "/stop":
                        self.agent.stop = True
                        self._send(chat, "Stop requested.")

                    elif cmd == "/status":
                        self._send(chat, f"Running: {self.agent.running}\nTarget: {self.agent.target or '?'}\n{self.agent.session.findings_summary()}")

                    elif cmd == "/findings":
                        self._send(chat, self.agent.session.findings_summary())

                    elif cmd == "/report":
                        self._send(chat, self.agent.session.report()[:3000])

                    elif cmd == "/help":
                        self._send(chat, "/scan <target>\n/stop\n/status\n/findings\n/report\n/help")

                time.sleep(CONFIG.TELEGRAM_POLL_INTERVAL_SEC)
            except KeyboardInterrupt:
                break
            except Exception:
                time.sleep(CONFIG.TELEGRAM_POLL_INTERVAL_SEC)


def _maybe_start_telegram(agent) -> Optional[TelegramBot]:
    has_token = os.getenv("TELEGRAM_BOT_TOKEN") or load_config().get("TELEGRAM_BOT_TOKEN")
    has_users = os.getenv("ALLOWED_TELEGRAM_USERS") or load_config().get("ALLOWED_TELEGRAM_USERS")
    if has_token and has_users:
        try:
            tg = TelegramBot(agent)
            t = threading.Thread(target=tg.run, daemon=True)
            t.start()
            print(f"{C.G}[+] Telegram bot active in background{C.N}")
            return tg
        except RuntimeError as e:
            print(f"{C.Y}[!] Telegram skipped: {e}{C.N}")
    return None


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
