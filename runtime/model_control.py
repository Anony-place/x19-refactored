"""Live model selection for an already-running X19 agent.

Model choice is mutable runtime state; changing it must never rebuild the agent,
lose mission state, or replace X19 with a generic chat client. The selected
provider/model is verified against the provider's current API before activation.
"""
from __future__ import annotations

from typing import Any


def _current_provider(backend: Any) -> str:
    working = getattr(backend, "_working", None)
    if working and isinstance(working, tuple) and working:
        return str(working[0])
    return str(getattr(backend, "primary_provider_id", "") or getattr(backend, "provider", ""))


def switch_model(agent: Any, model: str) -> str:
    """Verify and activate *model* on the existing X19 agent.

    Returns the provider/model display name. Raises ValueError on invalid or
    unavailable models. No agent/session/mission object is replaced.
    """
    if agent is None or getattr(agent, "ai", None) is None:
        raise ValueError("X19 has no active AI backend")
    model = str(model or "").strip()
    if not model:
        raise ValueError("model is required")

    backend = agent.ai
    provider = _current_provider(backend)
    if not provider:
        provider = str(getattr(backend, "primary_provider_id", "") or "")
    if not provider:
        provider = str(getattr(backend, "provider", "") or "")
    if not provider:
        raise ValueError("active provider could not be determined")

    # Import lazily so normal X19 startup does not perform network I/O.
    from provider_manager import _verify, discover_models
    from config import CONFIG, save_config

    ok, models, detail = discover_models(provider)
    if ok and models and model not in models:
        raise ValueError(f"model '{model}' is not currently exposed by {provider}")
    verified, verify_detail = _verify(provider, model)
    if not verified:
        raise ValueError(f"model verification failed for {provider}/{model}: {verify_detail}")

    # Update only the live backend/router. X19's identity, target, memory,
    # mission graph and session remain the same Python objects.
    if hasattr(backend, "_working"):
        backend._working = (provider, model)
        exhausted = getattr(backend, "_exhausted", None)
        if isinstance(exhausted, set):
            exhausted.discard((provider, model))
        if hasattr(backend, "primary_model"):
            backend.primary_model = model
        primary = getattr(backend, "primary", None)
        if primary is not None and hasattr(primary, "model"):
            primary.model = model
        if primary is not None and hasattr(primary, "provider"):
            primary.provider = provider
    else:
        if not hasattr(backend, "model"):
            raise ValueError("active backend does not support runtime model switching")
        backend.model = model
        if hasattr(backend, "provider"):
            backend.provider = provider

    CONFIG.AI_MODEL = model
    save_config({"AI_MODEL": model})
    try:
        agent._ai_runtime_model = model
        agent._ai_runtime_provider = provider
    except Exception:
        pass
    return f"{provider}/{model}"
