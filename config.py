from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict


@dataclass
class Config:
    AI_PROVIDER: str = os.getenv("X19_AI_PROVIDER", "huggingface")
    AI_MODEL: str = os.getenv("X19_AI_MODEL", "")
    TEMPERATURE: float = 0.4
    WORKSPACE: str = os.path.expanduser(os.getenv("X19_WORKSPACE", "~/x19_workspace"))
    SESSIONS_DIR: str = os.path.expanduser(os.getenv("X19_SESSIONS_DIR", "~/x19_sessions"))
    LOG_FILE: str = os.path.expanduser(os.getenv("X19_LOG_FILE", "~/x19_agent.log"))
    TIMEOUT_DEFAULT: int = int(os.getenv("X19_TIMEOUT", "120"))
    MAX_ITERATIONS: int = int(os.getenv("X19_MAX_ITERATIONS", "100"))

    TARGET_TYPE: str = os.getenv("X19_TARGET_TYPE", "auto")

    TELEGRAM_POLL_INTERVAL_SEC: int = 2
    TELEGRAM_LONGPOLL_TIMEOUT_SEC: int = 10
    TELEGRAM_MAX_MESSAGE_LEN: int = 3500

    # Database configuration
    DB_TYPE: str = os.getenv("X19_DB_TYPE", "sqlite")  # "sqlite" or "postgres"
    DB_HOST: str = os.getenv("X19_DB_HOST", "localhost")
    DB_PORT: int = int(os.getenv("X19_DB_PORT", "5432"))
    DB_NAME: str = os.getenv("X19_DB_NAME", "x19")
    DB_USER: str = os.getenv("X19_DB_USER", "x19")
    DB_PASSWORD: str = os.getenv("X19_DB_PASSWORD", "")
    DB_SQLITE_PATH: str = os.path.expanduser(os.getenv("X19_DB_SQLITE_PATH", "~/.x19/x19.db"))

    # Vector memory configuration
    VECTOR_MEMORY_TYPE: str = os.getenv("X19_VECTOR_MEMORY", "chromadb")  # "chromadb" or "pgvector"
    CHROMA_DIR: str = os.path.expanduser(os.getenv("X19_CHROMA_DIR", "~/.x19/memory"))

    # Bug bounty / CTF
    BUG_BOUNTY_MODE: bool = os.getenv("X19_BUG_BOUNTY_MODE", "").strip().lower() in ("1", "true", "yes")
    CTF_MODE: bool = os.getenv("X19_CTF_MODE", "").strip().lower() in ("1", "true", "yes")
    AUTO_BOOTSTRAP: bool = os.getenv("X19_AUTO_BOOTSTRAP", "1").strip().lower() not in ("0", "false", "no")

    PARALLEL_PLAN: bool = os.getenv("X19_PARALLEL_PLAN", "1").strip().lower() not in ("0", "false", "no")
    PARALLEL_WORKERS: int = max(1, int(os.getenv("X19_PARALLEL_WORKERS", "6")))
    MIN_ITERATIONS: int = int(os.getenv("X19_MIN_ITERATIONS", "8"))

    FAST_MODE: bool = os.getenv("X19_FAST_MODE", "").strip().lower() in ("1", "true", "yes")
    FAST_SKIP_PROXY: bool = os.getenv("X19_FAST_SKIP_PROXY", "").strip().lower() in ("1", "true", "yes")
    AI_MAX_TOKENS: int = int(os.getenv("X19_AI_MAX_TOKENS", "0") or "0")
    AI_TIMEOUT: int = int(os.getenv("X19_AI_TIMEOUT", "0") or "0")

    # Tool execution paths
    WORDLIST_DIR: str = os.getenv("X19_WORDLIST_DIR", "/usr/share/wordlists")
    TMP_DIR: str = os.getenv("X19_TMP_DIR", "/tmp")
    INTERFACE: str = os.getenv("X19_INTERFACE", "eth0")

    # Kali MCP remote execution
    MCP_KALI_SERVER: str = os.getenv("X19_MCP_KALI_SERVER", "kali")

    # Execution safety
    ENFORCE_SCOPE: bool = os.getenv("X19_ENFORCE_SCOPE", "").strip().lower() in ("1", "true", "yes")
    SCOPE_ALLOWLIST: str = os.getenv("X19_SCOPE_ALLOWLIST", "")


CONFIG: Config = Config()

CONFIG_DIR = Path(os.path.expanduser("~/.x19"))
CONFIG_FILE = CONFIG_DIR / "config.json"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)


# Data directories for scripts, payloads, wordlists
DATA_DIR = CONFIG_DIR / "data"
SCRIPTS_DIR = DATA_DIR / "scripts"
PAYLOADS_DIR = DATA_DIR / "payloads"
WORDLISTS_DIR = DATA_DIR / "wordlists"
for d in [SCRIPTS_DIR, PAYLOADS_DIR, WORDLISTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)


def load_config() -> Dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_config(data: Dict):
    existing = load_config()
    existing.update(data)
    CONFIG_FILE.write_text(json.dumps(existing, indent=2), encoding="utf-8")


def set_data(data: dict, save: bool = True):
    env_map = {
        "AI_PROVIDER": "X19_AI_PROVIDER",
        "AI_MODEL": "X19_AI_MODEL",
        "OPENROUTER_API_KEY": "OPENROUTER_API_KEY",
        "OPENAI_API_KEY": "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY": "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY": "GOOGLE_API_KEY",
        "GROQ_API_KEY": "GROQ_API_KEY",
        "DEEPSEEK_API_KEY": "DEEPSEEK_API_KEY",
        "TOGETHER_API_KEY": "TOGETHER_API_KEY",
        "AGENTROUTER_API_KEY": "AGENTROUTER_API_KEY",
        "NVIDIA_API_KEY": "NVIDIA_API_KEY",
        "DASHSCOPE_API_KEY": "DASHSCOPE_API_KEY",
        "DASHSCOPE_BASE_URL": "DASHSCOPE_BASE_URL",
        "TELEGRAM_BOT_TOKEN": "TELEGRAM_BOT_TOKEN",
        "ALLOWED_TELEGRAM_USERS": "ALLOWED_TELEGRAM_USERS",
        "TARGET": "X19_TARGET",
        "WORKSPACE": "X19_WORKSPACE",
        "SESSIONS_DIR": "X19_SESSIONS_DIR",
        "LOG_FILE": "X19_LOG_FILE",
        "TIMEOUT": "X19_TIMEOUT",
        "MAX_ITERATIONS": "X19_MAX_ITERATIONS",
        "PROVIDER": "X19_AI_PROVIDER",
        "MODEL": "X19_AI_MODEL",
        "TARGET_TYPE": "X19_TARGET_TYPE",
        "BUG_BOUNTY_MODE": "X19_BUG_BOUNTY_MODE",
        "CTF_MODE": "X19_CTF_MODE",
        "AUTO_BOOTSTRAP": "X19_AUTO_BOOTSTRAP",
        "PARALLEL_PLAN": "X19_PARALLEL_PLAN",
        "MIN_ITERATIONS": "X19_MIN_ITERATIONS",
        "FAST_MODE": "X19_FAST_MODE",
        "FAST_SKIP_PROXY": "X19_FAST_SKIP_PROXY",
        "AI_MAX_TOKENS": "X19_AI_MAX_TOKENS",
        "AI_TIMEOUT": "X19_AI_TIMEOUT",
        "WORDLIST_DIR": "X19_WORDLIST_DIR",
        "TMP_DIR": "X19_TMP_DIR",
        "INTERFACE": "X19_INTERFACE",
        "ENFORCE_SCOPE": "X19_ENFORCE_SCOPE",
        "SCOPE_ALLOWLIST": "X19_SCOPE_ALLOWLIST",
    }

    _bool_keys = {"BUG_BOUNTY_MODE", "CTF_MODE", "AUTO_BOOTSTRAP", "PARALLEL_PLAN", "FAST_MODE", "FAST_SKIP_PROXY", "ENFORCE_SCOPE"}

    for key, value in data.items():
        key_upper = key.upper()
        if key_upper in env_map:
            os.environ[env_map[key_upper]] = str(value)

        attr_key = key_upper
        if attr_key == "PROVIDER":
            attr_key = "AI_PROVIDER"
        elif attr_key == "MODEL":
            attr_key = "AI_MODEL"

        if hasattr(CONFIG, attr_key):
            if attr_key in _bool_keys:
                setattr(CONFIG, attr_key, str(value).lower() in ("1", "true", "yes"))
            elif attr_key in ("MIN_ITERATIONS", "AI_MAX_TOKENS", "AI_TIMEOUT"):
                setattr(CONFIG, attr_key, int(value))
            else:
                setattr(CONFIG, attr_key, value)

    if save:
        save_config(data)
