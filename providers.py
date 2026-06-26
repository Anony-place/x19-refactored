import json
import os
import re
import requests
import subprocess
import sys
import time
import threading
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any
from collections import Counter

from constants import C, ICO, PROVIDERS, PROVIDER_PRIORITY, _provider_has_key, _failover_disabled
from config import CONFIG, CONFIG_DIR, load_config, save_config
from logging_utils import log, swallow as _swallow


def _post_with_retry(poster, url, *, _retries: int = 3, **kwargs):
    """POST with exponential backoff on transient network errors and 5xx.
    Returns the final Response (caller handles status); re-raises on persistent network failure.
    Does NOT retry 4xx (incl. 429) so provider-specific fallback logic stays in control."""
    import random
    kwargs.setdefault("allow_redirects", False)
    for attempt in range(_retries):
        try:
            r = poster.post(url, **kwargs)
            # Handle redirects manually to preserve POST method
            if r.status_code in (301, 302, 307, 308) and "Location" in r.headers:
                url = r.headers["Location"]
                r = poster.post(url, **{k: v for k, v in kwargs.items() if k != "allow_redirects"}, allow_redirects=False)
            if r.status_code in (500, 502, 503, 504) and attempt < _retries - 1:
                time.sleep(2 ** attempt + random.uniform(0, 0.5))
                continue
            return r
        except requests.exceptions.RequestException:
            if attempt == _retries - 1:
                raise
            time.sleep(2 ** attempt + random.uniform(0, 0.5))


class AIBackend(ABC):
    @abstractmethod
    def chat(self, system: str, message: str) -> str: ...
    @abstractmethod
    def name(self) -> str: ...


OPENROUTER_FALLBACKS = [
    "deepseek/deepseek-chat:free",
    "deepseek/deepseek-v4-flash:free",
    "qwen/qwen3-coder:free",
    "meta-llama/llama-3.3-70b-instruct:free",
    "qwen/qwen3-next-80b-a3b-instruct:free",
    "moonshotai/kimi-k2.6:free",
    "openai/gpt-oss-120b:free",
    "nvidia/nemotron-3-super-120b-a3b:free",
    "nousresearch/hermes-3-llama-3.1-405b:free",
    "cognitivecomputations/dolphin-mistral-24b-venice-edition:free",
    "google/gemma-4-31b-it:free",
    "openrouter/free",
    "openrouter/owl-alpha",
]

NVIDIA_FALLBACKS = [
    "qwen/qwen3-coder-480b-a35b-instruct",
    "openai/gpt-oss-120b:free",
    "nvidia/nemotron-3-super-120b-a3b:free",
    "meta-llama/llama-3.3-70b-instruct:free",
    "qwen/qwen3-coder:free",
    "deepseek/deepseek-chat:free",
]

DASHSCOPE_FALLBACKS = [
    "qwen3-coder-next",
    "qwen3-coder-plus",
    "qwen-max",
    "qwen-plus",
]

# Free / cheapest model registry per provider (used by FailoverRouter for cross-provider auto-shift).
# Each list is tried in order: first one succeeds -> use it. All fail -> next provider.
PROVIDER_FREE_MODELS = {
    "openrouter": [
        # 404'd (2026-06): deepseek/deepseek-chat:free, deepseek/deepseek-v4-flash:free
        "qwen/qwen3-coder:free",
        "meta-llama/llama-3.3-70b-instruct:free",
        "qwen/qwen3-next-80b-a3b-instruct:free",
        "moonshotai/kimi-k2.6:free",
        "openai/gpt-oss-120b:free",
        "nvidia/nemotron-3-super-120b-a3b:free",
        "nousresearch/hermes-3-llama-3.1-405b:free",
        "cognitivecomputations/dolphin-mistral-24b-venice-edition:free",
        "google/gemma-4-31b-it:free",
        "openai/gpt-oss-20b:free",
        "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",
        "google/gemma-4-26b-a4b-it:free",
        "meta-llama/llama-3.2-3b-instruct:free",
        "liquid/lfm-2.5-1.2b-thinking:free",
        "openrouter/free",
        "openrouter/owl-alpha",
    ],
    "groq": [
        "llama-3.3-70b-versatile",
        "llama-3.1-8b-instant",
        # Decommissioned (2026-06): mixtral-8x7b-32768, gemma2-9b-it
    ],
    "google": [
        "gemini-1.5-flash",
        "gemini-1.5-flash-8b",
        "gemini-2.0-flash-exp",
        "gemini-1.5-pro",
    ],
    "nvidia": [
        "qwen/qwen3-coder-480b-a35b-instruct",
        "openai/gpt-oss-120b",
        "nvidia/nemotron-3-super-120b-a3b",
        "meta-llama/llama-3.3-70b-instruct",
        "qwen/qwen3-coder",
        "deepseek/deepseek-chat",
    ],
    "deepseek": [
        "deepseek-chat",
        "deepseek-reasoner",
    ],
    "together": [
        "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "Qwen/Qwen2.5-Coder-32B-Instruct",
        "mistralai/Mixtral-8x7B-Instruct-v0.1",
    ],
    "dashscope": [
        "qwen3-coder-next",
        "qwen3-coder-plus",
        "qwen-max",
        "qwen-plus",
    ],
    "agentrouter": [
        "gpt-4o-mini",
        "gpt-3.5-turbo",
    ],
    "huggingface": [
        "meta-llama/Llama-3.1-8B-Instruct",
        "microsoft/Phi-3.5-mini-instruct",
        "HuggingFaceH4/zephyr-7b-beta",
    ],
    "cerebras": [
        "llama-3.3-70b",
        "qwen-2.5-72b",
        "llama-3.1-8b",
    ],
    "openai": [
        "gpt-4o-mini",
        "gpt-3.5-turbo",
    ],
    "anthropic": [
        "claude-3-5-haiku-20241022",
        "claude-3-haiku-20240307",
    ],
}


class OpenAICompatBackend(AIBackend):
    """Works with any OpenAI-compatible API (OpenRouter, OpenAI, Groq, DeepSeek, Together, etc.)"""
    def __init__(self, provider: str, api_key: str, model: str = ""):
        info = PROVIDERS[provider]
        self.provider = provider
        self.format = "openai"
        self.label = info["name"]
        self.base = info["base_url"].rstrip("/")
        if provider == "dashscope":
            self.base = os.getenv("DASHSCOPE_BASE_URL", self.base).rstrip("/")
        self.model = model or CONFIG.AI_MODEL or info["default_model"]
        self.api_key = api_key
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update({"User-Agent": "X19-AI-Agent/1.0"})
        self._last_err = ""  # Surfaced in chain failure messages

    def name(self) -> str:
        return f"{self.label}/{self.model}"

    def _try_models(self, system: str, message: str) -> str:
        """Attempt request with fallback models on 404 or 429."""
        # Build ordered list: prefer current model first, then fallbacks
        models = [self.model]
        if self.provider == "nvidia":
            fallbacks = NVIDIA_FALLBACKS
        elif self.provider == "dashscope":
            fallbacks = DASHSCOPE_FALLBACKS
        else:
            fallbacks = OPENROUTER_FALLBACKS
        for m in fallbacks:
            if m not in models:
                models.append(m)

        # Track exhausted models to avoid re-trying them in same session
        if not hasattr(self, "_exhausted_models"):
            self._exhausted_models = set()

        last_detail = ""
        found_usable = False
        for attempt_model in models:
            if attempt_model in self._exhausted_models:
                continue
            found_usable = True
            try:
                r = _post_with_retry(self.session,
                    f"{self.base}/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                    json={
                        "model": attempt_model,
                        "messages": [{"role": "system", "content": system}, {"role": "user", "content": message}],
                        "max_tokens": ai_max_tokens(),
                        "temperature": CONFIG.TEMPERATURE,
                    },
                    timeout=ai_request_timeout(),
                )
                if r.status_code == 404:
                    detail = ""
                    try: detail = f": {r.json()}"
                    except: detail = str(r.text)
                    log(f"{self.label} model '{attempt_model}' 404{detail}")
                    print(f"{C.Y}[*] Model '{attempt_model}' unavailable, trying next...{C.N}")
                    last_detail = detail
                    continue
                if r.status_code in (402, 429):
                    detail = ""
                    try: detail = f": {r.json()}"
                    except: detail = str(r.text)
                    log(f"{self.label} model '{attempt_model}' rate-limited or spend-limit exceeded{detail}")
                    print(f"{C.Y}[*] Model '{attempt_model}' quota exceeded, trying next...{C.N}")
                    self._exhausted_models.add(attempt_model)
                    last_detail = detail
                    continue
                r.raise_for_status()
                # Save working model for this session
                if attempt_model != self.model:
                    self.model = attempt_model
                    print(f"{C.G}[+] Fallback succeeded: {self.model}{C.N}")
                return r.json()["choices"][0]["message"]["content"]
            except requests.exceptions.HTTPError as e:
                 detail = ""
                 try: detail = f": {e.response.json()}"
                 except: detail = str(e)
                 log(f"{self.label} HTTP error: {detail}")
                 status = e.response.status_code if hasattr(e, 'response') and e.response is not None else 0
                 if status >= 500:
                     self._exhausted_models.add(attempt_model)
                     print(f"{C.Y}[*] Model '{attempt_model}' returned {status}, trying next...{C.N}")
                     last_detail = detail
                     continue
                 print(f"{C.R}[!] {self.label} API error: {detail[:300]}{C.N}")
                 return ""
            except requests.exceptions.RequestException as e:
                  log(f"{self.label} request failed: {e}")
                  print(f"{C.Y}[*] {self.label} connection error: {e}, trying next...{C.N}")
                  if hasattr(self, '_exhausted_models'):
                      self._exhausted_models.add(attempt_model)
                  else:
                      self._exhausted_models = {attempt_model}
                  last_detail = str(e)
                  continue
            except Exception as e:
                log(f"{self.label}: {e}")
                print(f"{C.R}[!] {self.label} unexpected error: {e}{C.N}")
                return ""

        if not found_usable:
            print(f"{C.R}[!] All fallback models exhausted. Last error: {last_detail[:300]}{C.N}")
        return ""

    def _try_one_model(self, system: str, message: str, model: str) -> str:
        """Try exactly ONE model, no internal fallback. Returns content or '' on any failure.
        Used by FailoverRouter to maintain fine-grained control over the failover chain.
        Retries 429 up to 2 times with backoff (rate-limits are transient).
        Stashes the error reason in `self._last_err` so FailoverRouter can print it
        in the 'failed → next' message."""
        body = {
            "model": model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": message}],
            "max_tokens": ai_max_tokens(),
            "temperature": CONFIG.TEMPERATURE,
        }
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        url = f"{self.base}/chat/completions"
        last_err = ""
        for attempt in range(3):
            try:
                r = _post_with_retry(self.session, url, headers=headers, json=body,
                                     timeout=ai_request_timeout())
                if r.status_code == 404:
                    last_err = "404 not found"
                    break  # Permanent — don't retry
                if r.status_code == 429:
                    wait = 4 * (attempt + 1)  # 4s, 8s, 12s
                    last_err = "429 rate-limited"
                    if attempt < 2:
                        time.sleep(wait)
                        continue
                    break
                if r.status_code == 402:
                    last_err = "402 quota exceeded"
                    break
                if r.status_code in (500, 502, 503, 504):
                    last_err = f"{r.status_code} server error"
                    break  # _post_with_retry already retried
                if not r.ok:
                    last_err = f"{r.status_code} {r.text[:80]}"
                    break
                data = r.json()
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                if content:
                    self._last_err = ""
                    return content
                last_err = "empty response"
                break
            except requests.exceptions.RequestException as e:
                last_err = f"network: {type(e).__name__}"
                if attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
                break
            except Exception as e:
                last_err = f"{type(e).__name__}: {e}"
                break
        if last_err:
            log(f"{self.label}/{model} {last_err}")
        self._last_err = last_err
        return ""

    def chat(self, system: str, message: str) -> str:
        # Use fallback logic for all OpenAI-compatible providers
        if self.format == "openai":
            return self._try_models(system, message)
        # Non-OpenAI providers (Anthropic, Google, Ollama) do single request
        try:
              r = _post_with_retry(self.session,
                  f"{self.base}/chat/completions",
                  headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                  json={
                      "model": self.model,
                      "messages": [{"role": "system", "content": system}, {"role": "user", "content": message}],
                      "max_tokens": ai_max_tokens(),
                      "temperature": CONFIG.TEMPERATURE,
                  },
                  timeout=ai_request_timeout(),
              )
              r.raise_for_status()
              return r.json()["choices"][0]["message"]["content"]
        except requests.exceptions.HTTPError as e:
            detail = ""
            try: detail = f": {e.response.json()}"
            except: detail = str(e)
            log(f"{self.label} HTTP error: {detail}")
            print(f"{C.R}[!] {self.label} API error: {detail[:300]}{C.N}")
            return ""
        except requests.exceptions.RequestException as e:
            log(f"{self.label} request failed: {e}")
            print(f"{C.R}[!] {self.label} connection error: {e}{C.N}")
            return ""
        except Exception as e:
            log(f"{self.label}: {e}")
            print(f"{C.R}[!] {self.label} unexpected error: {e}{C.N}")
            return ""


class AnthropicBackend(AIBackend):
    def __init__(self, provider: str, api_key: str, model: str = ""):
        info = PROVIDERS[provider]
        self.label = info["name"]
        self.base = info["base_url"].rstrip("/")
        self.model = model or CONFIG.AI_MODEL or info["default_model"]
        self.api_key = api_key

    def name(self) -> str:
        return f"{self.label}/{self.model}"

    def _try_one_model(self, system: str, message: str, model: str) -> str:
        """Try exactly one Anthropic model, no fallback. Used by FailoverRouter."""
        try:
            r = _post_with_retry(requests,
                f"{self.base}/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "system": system,
                    "messages": [{"role": "user", "content": message}],
                    "max_tokens": ai_max_tokens(),
                },
                timeout=ai_request_timeout(),
                proxies={"http": None, "https": None},
            )
            if r.status_code in (401, 402, 403, 404, 429):
                log(f"{self.label}/{model} rejected ({r.status_code})")
                return ""
            r.raise_for_status()
            content = r.json().get("content", [])
            return content[0].get("text", "") if isinstance(content, list) and content else (content if isinstance(content, str) else "")
        except requests.exceptions.RequestException as e:
            log(f"{self.label}/{model} request failed: {e}")
            return ""
        except Exception as e:
            log(f"{self.label}/{model} unexpected: {type(e).__name__}: {e}")
            return ""

    def chat(self, system: str, message: str) -> str:
        try:
            r = _post_with_retry(requests,
                f"{self.base}/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "system": system,
                    "messages": [{"role": "user", "content": message}],
                    "max_tokens": ai_max_tokens(),
                },
                timeout=ai_request_timeout(),
                proxies={"http": None, "https": None},
            )
            r.raise_for_status()
            content = r.json()["content"]
            return content[0]["text"] if isinstance(content, list) else content
        except requests.exceptions.HTTPError as e:
            detail = ""
            try: detail = f": {e.response.json()}"
            except: detail = str(e)
            log(f"{self.label} HTTP error: {detail}")
            print(f"{C.R}[!] {self.label} API error: {detail[:300]}{C.N}")
            return ""
        except requests.exceptions.RequestException as e:
            log(f"{self.label} request failed: {e}")
            print(f"{C.R}[!] {self.label} connection error: {e}{C.N}")
            return ""
        except Exception as e:
            log(f"{self.label}: {e}")
            print(f"{C.R}[!] {self.label} unexpected error: {e}{C.N}")
            return ""


class GoogleBackend(AIBackend):
    def __init__(self, provider: str, api_key: str, model: str = ""):
        info = PROVIDERS[provider]
        self.label = info["name"]
        self.base = info["base_url"].rstrip("/")
        self.model = model or CONFIG.AI_MODEL or info["default_model"]
        self.api_key = api_key

    def name(self) -> str:
        return f"{self.label}/{self.model}"

    def _try_one_model(self, system: str, message: str, model: str) -> str:
        """Try exactly one Google model, no fallback. Used by FailoverRouter."""
        try:
            payload = {"contents": [{"parts": [{"text": f"{system}\n\n{message}"}]}]}
            r = _post_with_retry(requests,
                f"{self.base}/models/{model}:generateContent?key={self.api_key}",
                json=payload,
                timeout=ai_request_timeout(),
                proxies={"http": None, "https": None},
            )
            if r.status_code in (400, 403, 404, 429):
                log(f"{self.label}/{model} rejected ({r.status_code})")
                return ""
            r.raise_for_status()
            candidates = r.json().get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                return parts[0].get("text", "") if parts else ""
            return ""
        except requests.exceptions.RequestException as e:
            log(f"{self.label}/{model} request failed: {e}")
            return ""
        except Exception as e:
            log(f"{self.label}/{model} unexpected: {type(e).__name__}: {e}")
            return ""

    def chat(self, system: str, message: str) -> str:
        try:
            payload = {"contents": [{"parts": [{"text": f"{system}\n\n{message}"}]}]}
            r = _post_with_retry(requests,
                f"{self.base}/models/{self.model}:generateContent?key={self.api_key}",
                json=payload,
                timeout=ai_request_timeout(),
                proxies={"http": None, "https": None},
            )
            r.raise_for_status()
            candidates = r.json().get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                return parts[0].get("text", "") if parts else ""
            return ""
        except requests.exceptions.HTTPError as e:
            detail = ""
            try: detail = f": {e.response.json()}"
            except: detail = str(e)
            log(f"{self.label} HTTP error: {detail}")
            print(f"{C.R}[!] {self.label} API error: {detail[:300]}{C.N}")
            return ""
        except requests.exceptions.RequestException as e:
            log(f"{self.label} request failed: {e}")
            print(f"{C.R}[!] {self.label} connection error: {e}{C.N}")
            return ""
        except Exception as e:
            log(f"{self.label}: {e}")
            print(f"{C.R}[!] {self.label} unexpected error: {e}{C.N}")
            return ""


class OllamaBackend(AIBackend):
    def __init__(self, provider: str, model: str = ""):
        info = PROVIDERS[provider]
        self.label = info["name"]
        self.base = info["base_url"].rstrip("/")
        self.model = model or CONFIG.AI_MODEL or info["default_model"]

    def name(self) -> str:
        return f"{self.label}/{self.model}"

    def chat(self, system: str, message: str) -> str:
        try:
            r = _post_with_retry(requests,
                f"{self.base}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": message},
                    ],
                    "options": {"num_predict": ai_max_tokens(), "temperature": CONFIG.TEMPERATURE},
                    "stream": False,
                },
                timeout=ai_request_timeout(),
                proxies={"http": None, "https": None},
            )
            r.raise_for_status()
            data = r.json()
            msg = data.get("message", {})
            return msg.get("content", "")
        except requests.exceptions.RequestException as e:
            log(f"{self.label} connection failed: {e}")
            print(f"{C.R}[!] {self.label} connection error: {e}{C.N}")
            print(f"{C.Y}[*] Try: 1) 'ollama serve' is running  2) OLLAMA_ORIGINS=*  3) model '{self.model}' exists (ollama pull {self.model}){C.N}")
            return ""
        except Exception as e:
            log(f"{self.label}: {e}")
            print(f"{C.R}[!] {self.label} unexpected error: {e}{C.N}")
            return ""


class FailoverRouter(AIBackend):
    """Cross-provider auto-failover wrapper.
    Tries the primary backend's model first, then walks PROVIDER_FREE_MODELS across all
    configured providers. On 429/404/5xx or network error, immediately shifts to the next
    model; when all models of a provider are exhausted, shifts to the next provider.
    Skips Ollama. Persists the (provider, model) that succeeds for the rest of the session
    to avoid repeated rate-limits on the same model."""

    def __init__(self, primary: AIBackend, primary_provider_id: str = ""):
        self.primary = primary
        self.primary_provider_id = primary_provider_id or getattr(primary, "provider", "")
        self.primary_model = getattr(primary, "model", "")
        self.label = f"FailoverRouter({getattr(primary, 'label', 'AI')})"
        # Per-session: combos already tried & failed (so we don't re-hit them).
        self._exhausted: set = set()  # set of (provider_id, model) tuples
        self._working: Optional[Tuple[str, str]] = None  # (provider_id, model) that worked
        self._last_err_reasons: dict = {}  # (pid, model) -> short reason (rate-limit, 404, etc.)
        # Pre-built flat chain: list of (provider_id, model) in priority order.
        self._chain: List[Tuple[str, str]] = self._build_chain()
        self._suppressed = _failover_disabled()

    def name(self) -> str:
        if self._working:
            pid, m = self._working
            return f"{PROVIDERS[pid]['name']}/{m}"
        return self.primary.name()

    def _build_chain(self) -> List[Tuple[str, str]]:
        """Build the ordered (provider, model) chain. Primary first, then PROVIDER_PRIORITY.
        Skip Ollama. Skip providers without a configured key. De-duplicate.

        Edge case: if GROQ_API_KEY is configured AND Groq is the primary, the
        chain starts with all 4 Groq free models. If GROQ_API_KEY is set but
        AI_PROVIDER=openrouter, Groq still gets tried (after openrouter's 18)
        because of PROVIDER_PRIORITY order — user can run `x19 --setup-groq`
        to flip primary to Groq."""
        chain: List[Tuple[str, str]] = []
        seen: set = set()

        def add(pid: str, m: str):
            if (pid, m) in seen:
                return
            seen.add((pid, m))
            chain.append((pid, m))

        # 1. Primary provider's configured model first
        if self.primary_provider_id and self.primary_model:
            add(self.primary_provider_id, self.primary_model)

        # 2. Add primary provider's full free list (in case user model is a paid/non-listed one)
        if self.primary_provider_id in PROVIDER_FREE_MODELS:
            for m in PROVIDER_FREE_MODELS[self.primary_provider_id]:
                add(self.primary_provider_id, m)

        # 3. Then the remaining providers in priority order
        for pid in PROVIDER_PRIORITY:
            if pid == self.primary_provider_id:
                continue
            if pid == "ollama":
                continue
            if pid not in PROVIDERS:
                continue
            if not _provider_has_key(pid):
                continue
            for m in PROVIDER_FREE_MODELS.get(pid, []):
                add(pid, m)

        return chain

    def _try_one(self, provider_id: str, model: str, system: str, message: str) -> str:
        """Instantiate the right backend for (provider, model) and try ONE request.
        Returns content string or '' on any failure. Also records the failure
        reason in self._last_err_reasons[(pid, m)] for chain-printer use."""
        be = None
        try:
            info = PROVIDERS[provider_id]
            if info.get("needs_key"):
                key = _get_key_for(provider_id)
                if not key:
                    self._last_err_reasons[(provider_id, model)] = "no API key"
                    return ""
            else:
                key = ""
            fmt = info["format"]
            if fmt == "openai":
                be = OpenAICompatBackend(provider_id, key, model)
                result = be._try_one_model(system, message, model)
            elif fmt == "anthropic":
                be = AnthropicBackend(provider_id, key, model)
                result = be._try_one_model(system, message, model)
            elif fmt == "google":
                be = GoogleBackend(provider_id, key, model)
                result = be._try_one_model(system, message, model)
            else:
                self._last_err_reasons[(provider_id, model)] = f"unsupported format {fmt}"
                return ""
            if be is not None and getattr(be, "_last_err", ""):
                self._last_err_reasons[(provider_id, model)] = be._last_err
            elif not result:
                self._last_err_reasons[(provider_id, model)] = "unknown"
            return result
        except Exception as e:
            self._last_err_reasons[(provider_id, model)] = f"{type(e).__name__}: {e}"
            log(f"FailoverRouter {provider_id}/{model}: {type(e).__name__}: {e}")
        return ""

    def chat(self, system: str, message: str) -> str:
        # If user disabled failover, just use primary
        if self._suppressed:
            return self.primary.chat(system, message)

        for attempt in range(2):
            # If we already found a working combo earlier, try it first (cheaper path)
            ordered_chain = list(self._chain)
            if self._working:
                wp, wm = self._working
                # Move working combo to front
                if (wp, wm) in ordered_chain:
                    ordered_chain.remove((wp, wm))
                ordered_chain.insert(0, (wp, wm))

            any_tried = False
            for pid, m in ordered_chain:
                if (pid, m) in self._exhausted:
                    continue
                any_tried = True
                result = self._try_one(pid, m, system, message)
                if result:
                    # Got a working response
                    self._working = (pid, m)
                    # Update primary backend so legacy callers (logs, /model) see the active model
                    if hasattr(self.primary, "model"):
                        self.primary.model = m
                    if hasattr(self.primary, "provider") and self.primary.provider != pid:
                        self.primary.provider = pid
                    print(f"{C.D}[router] {PROVIDERS[pid]['name']}/{m}{C.N}", flush=True)
                    return result
                # Mark this combo as exhausted; try next
                self._exhausted.add((pid, m))
                reason = self._last_err_reasons.get((pid, m), "")
                if reason:
                    print(f"{C.Y}[router] {PROVIDERS[pid]['name']}/{m} failed ({reason}) → next{C.N}", flush=True)
                else:
                    print(f"{C.Y}[router] {PROVIDERS[pid]['name']}/{m} failed → next{C.N}", flush=True)

            if not any_tried:
                # All combos already exhausted from prior cycle — clear and retry once
                print(f"{C.Y}[router] All previously exhausted — retrying all providers/models...{C.N}", flush=True)
                self._exhausted.clear()
                self._working = None
                continue

            # Actually tried all and all failed — give up
            break

        print(f"{C.R}[!] FailoverRouter: all providers & models exhausted.{C.N}", flush=True)
        return ""

    def reset(self):
        """Re-enable previously exhausted models (e.g. after a sleep / new session)."""
        self._exhausted.clear()
        self._working = None
        self._last_err_reasons.clear()


OPENROUTER_MODELS = [
    "deepseek/deepseek-chat:free",
    "deepseek/deepseek-v4-flash:free",
    "qwen/qwen3-coder:free",
    "meta-llama/llama-3.3-70b-instruct:free",
    "qwen/qwen3-next-80b-a3b-instruct:free",
    "moonshotai/kimi-k2.6:free",
    "openai/gpt-oss-120b:free",
    "nvidia/nemotron-3-super-120b-a3b:free",
    "nousresearch/hermes-3-llama-3.1-405b:free",
    "cognitivecomputations/dolphin-mistral-24b-venice-edition:free",
    "google/gemma-4-31b-it:free",
    "openai/gpt-oss-20b:free",
    "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",
    "google/gemma-4-26b-a4b-it:free",
    "meta-llama/llama-3.2-3b-instruct:free",
    "liquid/lfm-2.5-1.2b-thinking:free",
    "openrouter/free",
    "openrouter/owl-alpha",
    "Custom model",
]

OOB_DISABLED = os.getenv("X19_DISABLE_OOB", "").strip().lower() in ("1", "true", "yes")
IDOR_DISABLED = os.getenv("X19_DISABLE_IDOR", "").strip().lower() in ("1", "true", "yes")
JWT_DISABLED = os.getenv("X19_DISABLE_JWT", "").strip().lower() in ("1", "true", "yes")


def is_bug_bounty_mode() -> bool:
    return CONFIG.BUG_BOUNTY_MODE or os.getenv("X19_BUG_BOUNTY_MODE", "").strip().lower() in ("1", "true", "yes")


def is_ctf_mode() -> bool:
    """CTF mode: aggressive exploitation, flag hunting, full testing."""
    return CONFIG.CTF_MODE or os.getenv("X19_CTF_MODE", "").strip().lower() in ("1", "true", "yes")


def is_fast_mode() -> bool:
    """Faster planning/decisions: compact prompt, smaller context, no extra LLM verify."""
    if CONFIG.FAST_MODE or os.getenv("X19_FAST_MODE", "").strip().lower() in ("1", "true", "yes"):
        return True
    return is_bug_bounty_mode() or is_ctf_mode()


def ai_max_tokens() -> int:
    if CONFIG.AI_MAX_TOKENS > 0:
        return CONFIG.AI_MAX_TOKENS
    return 1024 if is_fast_mode() else 2048


def ai_request_timeout() -> int:
    if CONFIG.AI_TIMEOUT > 0:
        return CONFIG.AI_TIMEOUT
    return 45 if is_fast_mode() else 90


_JWT_SCAN_HISTORY: set = set()


def jwt_auto_scan(text: str) -> List[dict]:
    """Run JWT attack on any newly-seen tokens. Deduplicates per session."""
    if JWT_DISABLED:
        return []
    from attacks import JWTAttacker
    attacker = JWTAttacker()
    findings: List[dict] = []
    for tok in attacker.extract(text):
        if tok in _JWT_SCAN_HISTORY:
            continue
        _JWT_SCAN_HISTORY.add(tok)
        findings.extend(attacker.attack(tok))
    return findings


# Auth-aware inventory: endpoints captured by mitmproxy that returned 2xx with a session cookie
def endpoints_from_collector(collector, max_n: int = 200) -> List[str]:
    """Pull unique authenticated 2xx URLs from a TrafficCollector (mitmproxy)."""
    seen: set = set()
    out: List[str] = []
    if collector is None:
        return out
    for entry in getattr(collector, "entries", []):
        if 200 <= getattr(entry, "status", 0) < 300 and getattr(entry, "url", ""):
            # Strip query for dedup
            from urllib.parse import urlsplit
            base = urlsplit(entry.url)._replace(query="").geturl()
            if base in seen:
                continue
            seen.add(base)
            out.append(base)
            if len(out) >= max_n:
                break
    return out


def _prompt_model(provider_id: str, default_model: str) -> str:
    saved = load_config().get("AI_MODEL", "")
    if saved:
        use = input(f"{C.B}[?] Use saved model '{saved}'? (Y/n): {C.N}").strip().lower()
        if use != "n":
            return saved

    if provider_id == "openrouter":
        print(f"\n{C.BOLD}{C.Y}Select OpenRouter model:{C.N}")
        for i, m in enumerate(OPENROUTER_MODELS, 1):
            mark = " *" if m == default_model else ""
            free = " (free)" if "free" in m else ""
            print(f"  {C.G}[{i}]{C.N} {m}{free}{mark}")
        choice = input(f"\n{C.B}[?] Model (1-{len(OPENROUTER_MODELS)}) or press Enter for default: {C.N}").strip()
        if choice:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(OPENROUTER_MODELS):
                    selected = OPENROUTER_MODELS[idx]
                    if selected == "Custom model":
                        selected = input(f"{C.B}[?] Enter model name: {C.N}").strip()
                    if selected:
                        save_config({"AI_MODEL": selected})
                        return selected
            except ValueError:
                pass
        return default_model

    # For other providers: just ask if they want custom
    print(f"{C.Y}[*] Default model: {default_model}{C.N}")
    custom = input(f"{C.B}[?] Enter custom model (or press Enter for default): {C.N}").strip()
    if custom:
        save_config({"AI_MODEL": custom})
        return custom
    return default_model


def _get_key_for(provider_id: str) -> str:
    info = PROVIDERS[provider_id]
    env = info["api_key_env"]
    cfg_key = info["api_key_config"]

    key = os.getenv(env) if env else ""
    if not key and cfg_key:
        key = load_config().get(cfg_key, "")
    return key


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


def make_ai(provider_id: str = "") -> AIBackend:
    # Use saved provider if none specified
    if not provider_id:
        provider_id = load_config().get("AI_PROVIDER", CONFIG.AI_PROVIDER)

    # Show provider menu if forced or invalid
    if provider_id == "__menu__":
        provider_id = ""

    if provider_id and provider_id not in PROVIDERS:
        valid = [p for p in PROVIDERS if p != "ollama"]
        print(f"{C.R}[!] Unknown AI provider '{provider_id}' in config{C.N}")
        print(f"{C.Y}    Valid providers: {', '.join(valid)}{C.N}")
        print(f"{C.Y}    Fix with: x19 --set-data '{{\"AI_PROVIDER\": \"groq\"}}'{C.N}")
        sys.exit(1)

    if not provider_id:
        # Try env
        for pid in PROVIDERS:
            env_key = PROVIDERS[pid].get("api_key_env", "")
            if env_key and os.getenv(env_key):
                provider_id = pid
                break
        if not provider_id:
            # Last resort: check if any key env var is set
            for pid in PROVIDERS:
                info = PROVIDERS[pid]
                if not info["needs_key"]:
                    provider_id = pid
                    break
            if not provider_id:
                provider_id = "openrouter"

        save_config({"AI_PROVIDER": provider_id})

    info = PROVIDERS[provider_id]
    fmt = info["format"]

    # If Ollama is saved but not reachable, auto-switch to a key-based provider
    if provider_id == "ollama":
        try:
            base = info["base_url"].rstrip("/")
            r = requests.get(f"{base}/api/tags", timeout=3)
            r.raise_for_status()
            ollama_models = [m["name"] for m in r.json().get("models", [])]
            default_model = CONFIG.AI_MODEL or info["default_model"]
            saved_model = load_config().get("AI_MODEL", "")
            actual_model = saved_model or default_model
            if not any(actual_model in m for m in ollama_models):
                print(f"{C.Y}[*] Model '{actual_model}' not found in Ollama. "
                      f"Available: {', '.join(ollama_models[:8])}{C.N}")
                print(f"{C.Y}[*] Run: ollama pull {actual_model}{C.N}")
                print(f"{C.Y}[*] Or use a different model via: /model <name>{C.N}")
            # Don't fallback on missing model — user needs to pull or select a different model
        except requests.exceptions.HTTPError:
            print(f"{C.Y}[*] Ollama at {info['base_url']} returned HTTP {r.status_code}. "
                  f"Check OLLAMA_ORIGINS env var (set to '*') or if model exists. Falling back...{C.N}")
            provider_id = "openrouter"
            info = PROVIDERS[provider_id]
            fmt = info["format"]
            save_config({"AI_PROVIDER": provider_id, "AI_MODEL": ""})
        except Exception:
            print(f"{C.Y}[*] Ollama not running at {info['base_url']}. Falling back to OpenRouter...{C.N}")
            provider_id = "openrouter"
            info = PROVIDERS[provider_id]
            fmt = info["format"]
            save_config({"AI_PROVIDER": provider_id, "AI_MODEL": ""})
            info = PROVIDERS[provider_id]
            fmt = info["format"]
            save_config({"AI_PROVIDER": provider_id, "AI_MODEL": ""})

    # Get API key if needed
    key = ""
    if info["needs_key"]:
        key = _get_key_for(provider_id)
        if not key:
            # Non-interactive fail
            print(f"{C.R}[!] {info['name']} API key not found.{C.N}")
            print(f"{C.Y}[*] Set it via:{C.N}")
            print(f"  python x19.py --set-data '{{\"{info['api_key_env']}\": \"your-key\"}}'")
            print(f"  Or set env var: {info['api_key_env']}=your-key")
            sys.exit(1)

    # Model selection (non-interactive when pre-configured)
    default_model = CONFIG.AI_MODEL or info["default_model"]
    saved_model = load_config().get("AI_MODEL", "")
    model = saved_model or default_model
    if model:
        CONFIG.AI_MODEL = model

    # Create backend
    backend = None
    if info["needs_key"]:
        if fmt == "anthropic":
            backend = AnthropicBackend(provider_id, key, model)
        elif fmt == "google":
            backend = GoogleBackend(provider_id, key, model)
        else:
            backend = OpenAICompatBackend(provider_id, key, model)
    else:
        if fmt == "ollama":
            backend = OllamaBackend(provider_id, model)

    if not backend:
        print(f"{C.R}[!] Unknown provider format: {fmt}{C.N}")
        sys.exit(1)

    # Wrap in FailoverRouter for cross-provider auto-shift (free models, skip Ollama).
    # Set X19_DISABLE_FAILOVER=1 to disable and use the raw primary backend.
    if not _failover_disabled() and provider_id != "ollama":
        # Stash the original provider_id on the backend so the router knows where to start
        if not hasattr(backend, "provider"):
            try:
                backend.provider = provider_id
            except Exception as e:
                _swallow(e)
        try:
            router = FailoverRouter(backend, primary_provider_id=provider_id)
            return router
        except Exception as e:
            log(f"FailoverRouter init failed: {e}; falling back to raw backend")

    return backend
