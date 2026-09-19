"""Tests for the Nous-Hermes-3/4 non-agentic warning detector.

Prior to this check, the warning fired on any model whose name merely contained
the Nous chat family's name somewhere (case-insensitive). That false-positived
on unrelated local Modelfiles such as a ``<family>-brain:qwen3-14b-ctx16k``
wrapper — a tool-capable Qwen3 model that happens to live under that tag
namespace.

``is_nous_x19_non_agentic`` should only match the actual Nous Research
Hermes-3 / Hermes-4 chat family. The family name is the provider's, so the
detector matches it verbatim; nothing in this product is named after it, and a
brand rename that rewrote the pattern silently disabled the warning.
"""

from __future__ import annotations

import pytest

from x19_cli.model_switch import (
    _X19_MODEL_WARNING,
    _check_x19_model_warning,
    is_nous_x19_non_agentic,
)


@pytest.mark.parametrize(
    "model_name",
    [
        "NousResearch/Hermes-3-Llama-3.1-70B",
        "NousResearch/Hermes-3-Llama-3.1-405B",
        "hermes-3",
        "Hermes-3",
        "hermes-4",
        "hermes-4-405b",
        "hermes_4_70b",
        "openrouter/hermes3:70b",
        "openrouter/nousresearch/hermes-4-405b",
        "NousResearch/Hermes3",
        "hermes-3.1",
    ],
)
def test_matches_real_nous_x19_chat_models(model_name: str) -> None:
    assert is_nous_x19_non_agentic(model_name), (
        f"expected {model_name!r} to be flagged as Nous Hermes 3/4"
    )
    assert _check_x19_model_warning(model_name) == _X19_MODEL_WARNING


@pytest.mark.parametrize(
    "model_name",
    [
        "qwen3:14b",
        "claude-opus-4-6",
        "gpt-5",
        "deepseek-v3",
        # The false-positive class the tightened pattern exists for: a
        # tool-capable local Modelfile living under a *-brain tag namespace.
        "hermes-brain:qwen3-14b-ctx16k",
        "x19-brain:qwen3-14b-ctx16k",
        # A version outside the non-agentic 3/4 families.
        "hermes-2-pro",
        "",
    ],
)
def test_does_not_flag_agentic_models(model_name: str) -> None:
    assert not is_nous_x19_non_agentic(model_name), (
        f"{model_name!r} is agentic (or unnamed) and must not trigger the warning"
    )
    assert _check_x19_model_warning(model_name) == ""


