"""Plugin system for x19 — hot-reloadable Python modules that hook into agent lifecycle.

Plugins live in `plugins/` directory. Each plugin is a Python file that exports
hook functions:

    def on_start(agent):            # Called when agent loop starts
    def on_end(agent, status):      # Called when agent loop ends
    def on_tool_result(agent, cmd, result):  # After each tool execution
    def on_context_build(agent, ctx):        # Before context is sent to AI
    def on_decision(agent, decision):        # After AI makes a decision
    def on_finding(agent, finding):          # When a finding is confirmed
    def on_iteration(agent, iteration):      # At the start of each iteration
"""

import importlib
import importlib.util
import inspect
import os
import sys
import time
import traceback
from pathlib import Path
from typing import Optional, Dict, List, Any, Callable

from config import CONFIG
from logging_utils import log


HOOKS = [
    "on_start",
    "on_end",
    "on_tool_result",
    "on_context_build",
    "on_decision",
    "on_finding",
    "on_iteration",
]

PLUGINS_DIR = Path(CONFIG.CONFIG_DIR if hasattr(CONFIG, "CONFIG_DIR") and CONFIG.CONFIG_DIR else ".") / "plugins"


class Plugin:
    def __init__(self, name: str, module, filepath: Path):
        self.name = name
        self.module = module
        self.filepath = filepath
        self.enabled = True
        self.error_count = 0
        self.last_error: str = ""
        self._hooks: Dict[str, Callable] = {}

        for hook in HOOKS:
            fn = getattr(module, hook, None)
            if fn and callable(fn):
                sig = inspect.signature(fn)
                self._hooks[hook] = fn

    def has_hook(self, name: str) -> bool:
        return name in self._hooks

    def call_hook(self, name: str, *args, **kwargs) -> Optional[Any]:
        if not self.enabled or name not in self._hooks:
            return None
        try:
            return self._hooks[name](*args, **kwargs)
        except Exception as e:
            self.error_count += 1
            self.last_error = f"{e}\n{traceback.format_exc()[:200]}"
            log(f"[Plugin:{self.name}] Hook '{name}' error: {e}")
            if self.error_count >= 5:
                self.enabled = False
                log(f"[Plugin:{self.name}] Disabled after {self.error_count} errors")
            return None

    def reload(self):
        try:
            self.module = importlib.reload(self.module)
            for hook in HOOKS:
                fn = getattr(self.module, hook, None)
                if fn and callable(fn):
                    self._hooks[hook] = fn
                elif hook in self._hooks:
                    del self._hooks[hook]
            self.error_count = 0
            self.enabled = True
            log(f"[Plugin:{self.name}] Reloaded")
            return True
        except Exception as e:
            log(f"[Plugin:{self.name}] Reload failed: {e}")
            return False


class PluginManager:
    """Loads, tracks, and invokes plugins."""

    def __init__(self, agent=None):
        self.agent = agent
        self._plugins: Dict[str, Plugin] = {}
        self._watcher_active = False
        self._load_all()

    def _load_all(self):
        if not PLUGINS_DIR.exists():
            PLUGINS_DIR.mkdir(parents=True, exist_ok=True)
            # Create sample plugin
            self._create_sample()
            return

        for fpath in sorted(PLUGINS_DIR.glob("*.py")):
            if fpath.name.startswith("_"):
                continue
            self._load_plugin(fpath)

        log(f"[Plugins] Loaded {len(self._plugins)} plugin(s)")

    def _load_plugin(self, fpath: Path):
        name = fpath.stem
        if name in self._plugins:
            return self._plugins[name].reload()

        spec = importlib.util.spec_from_file_location(name, fpath)
        if not spec or not spec.loader:
            return None

        try:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            plugin = Plugin(name, module, fpath)
            self._plugins[name] = plugin
            log(f"[Plugin] Loaded: {name}")
            return plugin
        except Exception as e:
            log(f"[Plugin] Failed to load {name}: {e}")
            return None

    def reload_all(self):
        for name in list(self._plugins.keys()):
            plugin = self._plugins[name]
            plugin.reload()
        log(f"[Plugins] Reloaded all")

    def get_plugin(self, name: str) -> Optional[Plugin]:
        return self._plugins.get(name)

    def call_hook(self, hook: str, *args, **kwargs):
        for name, plugin in self._plugins.items():
            try:
                plugin.call_hook(hook, *args, **kwargs)
            except Exception as e:
                log(f"[Plugin:{name}] Hook error: {e}")

    def call_hook_filter(self, hook: str, *args, **kwargs) -> Optional[Any]:
        """Call hook and return last non-None result (acts as filter chain)."""
        result = None
        for name, plugin in self._plugins.items():
            try:
                r = plugin.call_hook(hook, *args, **kwargs)
                if r is not None:
                    result = r
            except Exception as e:
                log(f"[Plugin:{name}] Hook error: {e}")
        return result

    @property
    def enabled_plugins(self) -> List[Plugin]:
        return [p for p in self._plugins.values() if p.enabled]

    def summary(self) -> str:
        if not self._plugins:
            return "No plugins loaded"
        lines = [f"Plugins ({len(self._plugins)}):"]
        for name, p in self._plugins.items():
            hooks = [h for h in HOOKS if p.has_hook(h)]
            status = "OK" if p.enabled else "DISABLED"
            lines.append(f"  [{status}] {name} ({len(hooks)} hooks: {', '.join(hooks)})")
        return "\n".join(lines)

    @staticmethod
    def _create_sample():
        sample = PLUGINS_DIR / "sample_notifier.py"
        if sample.exists():
            return
        content = '''"""Sample x19 plugin — sends notifications on findings."""
import subprocess
import json


def on_start(agent):
    print("[Plugin] Sample plugin loaded — will notify on critical findings")


def on_finding(agent, finding):
    if finding.severity in ("critical", "high"):
        msg = f"x19: {finding.severity.upper()} — {finding.title}"
        print(f"[Plugin:Notifier] {msg}")
        # Example: send to Telegram
        # bot_token = "YOUR_BOT_TOKEN"
        # chat_id = "YOUR_CHAT_ID"
        # subprocess.run([
        #     "curl", "-s",
        #     f"https://api.telegram.org/bot{bot_token}/sendMessage",
        #     "--data-urlencode", f"chat_id={chat_id}",
        #     "--data-urlencode", f"text={msg}"
        # ], timeout=10)


def on_context_build(agent, ctx):
    """Add plugin info to AI context."""
    return "\\n[Plugin: Sample notifier active — findings will be notified]\\n"
'''
        sample.write_text(content, encoding="utf-8")
