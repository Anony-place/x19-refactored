"""Tests for brain.frontier_gate.

Some models are rated Critical for cyber by their vendor, and access to advanced
cyber workflows through them is gated behind tiers X19 cannot inspect. X19 cannot
prove a user is authorised, so it fails closed: exploitation is refused through
such a model unless the engagement is explicitly classified as authorised.

Two phase vocabularies exist in the agent — ``_current_phase`` uses
``recon|hypothesis|validation|exploitation`` while the tool tables use
``recon|enum|vuln|exploit|report`` — so both spellings of the exploitation phase
must gate.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from brain.frontier_gate import (
    AUTHORIZED_TYPES,
    CRITICAL_CYBER_MODELS,
    EXPLOITATION_PHASES,
    TIER_CRITICAL,
    TIER_STANDARD,
    check_model_for_phase,
    check_model_for_target_data,
    gate_status,
    is_critical_cyber_model,
    model_tier,
)

ASTRA = "gpt-6-astra"
ORDINARY = "gpt-4o"

#: Phases that must never be blocked, whichever model is in use.
OBSERVATIONAL_PHASES = ("recon", "enum", "vuln", "report", "hypothesis", "validation")


class ModelTierTests(unittest.TestCase):
    def test_every_listed_model_is_recognised(self):
        for pattern, label in CRITICAL_CYBER_MODELS:
            self.assertTrue(is_critical_cyber_model(pattern), pattern)
            self.assertEqual(model_tier(pattern), TIER_CRITICAL, pattern)
            self.assertTrue(label.strip(), pattern)

    def test_matching_is_a_substring_match(self):
        """Vendor ids carry dates and suffixes; the bare name must still match."""
        for candidate in (
            "gpt-6-astra", "openai/gpt-6-astra-2026-09-03", "GPT-6-Astra",
            " gpt-6-astra ", "claude-mythos-5.1", "openai/daybreak-red",
        ):
            self.assertTrue(is_critical_cyber_model(candidate), candidate)

    def test_ordinary_models_are_not_gated(self):
        for candidate in ("gpt-4o", "claude-3-sonnet-20240229", "gemini-1.5-flash",
                          "llama-3.3-70b-versatile", "meta-llama/Llama-3.1-8B-Instruct"):
            self.assertFalse(is_critical_cyber_model(candidate), candidate)
            self.assertEqual(model_tier(candidate), TIER_STANDARD, candidate)

    def test_empty_and_none_are_standard_tier(self):
        for candidate in ("", None, "   "):
            self.assertFalse(is_critical_cyber_model(candidate))
            self.assertEqual(model_tier(candidate), TIER_STANDARD)

    def test_astra_is_the_flagship_critical_model(self):
        self.assertIn(ASTRA, [p for p, _ in CRITICAL_CYBER_MODELS])


class PhaseGateTests(unittest.TestCase):
    def test_ordinary_model_is_never_blocked(self):
        for target_type in ("auto", "public_real_world", "authorized", "ctf", "lab", ""):
            for phase in OBSERVATIONAL_PHASES + EXPLOITATION_PHASES:
                verdict = check_model_for_phase(ORDINARY, target_type, phase)
                self.assertTrue(verdict.allowed, f"{target_type}/{phase}")

    def test_observational_phases_are_never_blocked(self):
        for target_type in ("auto", "public_real_world", "authorized", ""):
            for phase in OBSERVATIONAL_PHASES:
                verdict = check_model_for_phase(ASTRA, target_type, phase)
                self.assertTrue(verdict.allowed, f"{target_type}/{phase}")
                self.assertEqual(verdict.tier, TIER_CRITICAL)

    def test_exploitation_is_blocked_without_authorisation(self):
        for target_type in ("auto", "public_real_world", "", None):
            for phase in EXPLOITATION_PHASES:
                verdict = check_model_for_phase(ASTRA, target_type, phase)
                self.assertFalse(verdict.allowed, f"{target_type}/{phase}")
                self.assertEqual(verdict.tier, TIER_CRITICAL)
                self.assertTrue(verdict.reason.strip())
                self.assertTrue(verdict.requires.strip())

    def test_both_phase_spellings_gate(self):
        """The agent uses 'exploitation'; the tool tables use 'exploit'."""
        self.assertIn("exploit", EXPLOITATION_PHASES)
        self.assertIn("exploitation", EXPLOITATION_PHASES)
        for phase in ("exploit", "exploitation"):
            self.assertFalse(check_model_for_phase(ASTRA, "auto", phase).allowed, phase)

    def test_exploitation_is_allowed_with_authorisation(self):
        for target_type in AUTHORIZED_TYPES:
            for phase in EXPLOITATION_PHASES:
                verdict = check_model_for_phase(ASTRA, target_type, phase)
                self.assertTrue(verdict.allowed, f"{target_type}/{phase}")

    def test_target_type_matching_ignores_case_and_padding(self):
        for target_type in ("  AUTHORIZED ", "Authorized", "CTF"):
            self.assertTrue(
                check_model_for_phase(ASTRA, target_type, "exploit").allowed, target_type)

    def test_unknown_phase_is_treated_as_observational(self):
        self.assertTrue(check_model_for_phase(ASTRA, "auto", "something-new").allowed)
        self.assertTrue(check_model_for_phase(ASTRA, "auto", "").allowed)

    def test_requires_text_names_the_fix(self):
        verdict = check_model_for_phase(ASTRA, "auto", "exploit")
        for target_type in AUTHORIZED_TYPES:
            self.assertIn(target_type, verdict.requires)
        self.assertIn("x19", verdict.requires)

    def test_verdict_carries_the_model_back(self):
        verdict = check_model_for_phase(ASTRA, "auto", "exploit")
        self.assertEqual(verdict.model, ASTRA)


class TargetDataGateTests(unittest.TestCase):
    def test_public_real_world_target_data_is_refused(self):
        verdict = check_model_for_target_data(ASTRA, "public_real_world")
        self.assertFalse(verdict.allowed)
        self.assertTrue(verdict.reason.strip())

    def test_other_target_types_are_allowed(self):
        for target_type in ("auto", "authorized", "ctf", "lab", ""):
            self.assertTrue(
                check_model_for_target_data(ASTRA, target_type).allowed, target_type)

    def test_ordinary_model_is_unrestricted(self):
        self.assertTrue(check_model_for_target_data(ORDINARY, "public_real_world").allowed)


class GateStatusTests(unittest.TestCase):
    def test_shape(self):
        status = gate_status(ASTRA, "auto")
        self.assertEqual(
            {"model", "tier", "gated", "label", "exploitation_allowed",
             "target_data_allowed", "reason", "requires", "target_type"},
            set(status),
        )

    def test_critical_model_unauthorised(self):
        status = gate_status(ASTRA, "auto")
        self.assertTrue(status["gated"])
        self.assertFalse(status["exploitation_allowed"])
        self.assertEqual(status["tier"], TIER_CRITICAL)
        self.assertIn("Astra", status["label"])

    def test_critical_model_authorised(self):
        status = gate_status(ASTRA, "ctf")
        self.assertTrue(status["gated"])
        self.assertTrue(status["exploitation_allowed"])
        self.assertEqual(status["target_type"], "ctf")

    def test_ordinary_model(self):
        status = gate_status(ORDINARY, "auto")
        self.assertFalse(status["gated"])
        self.assertTrue(status["exploitation_allowed"])
        self.assertEqual(status["tier"], TIER_STANDARD)

    def test_label_is_never_empty(self):
        """`doctor` prints this directly, so an empty label reads as a bug."""
        for model in (ASTRA, ORDINARY, "", None, "some-unknown-model"):
            self.assertTrue(gate_status(model, "auto")["label"].strip(), repr(model))

    def test_target_type_defaults_to_auto(self):
        self.assertEqual(gate_status(ASTRA, None)["target_type"], "auto")
        self.assertEqual(gate_status(ASTRA, "")["target_type"], "auto")

    def test_target_data_flag_reflects_public_real_world(self):
        self.assertFalse(gate_status(ASTRA, "public_real_world")["target_data_allowed"])
        self.assertTrue(gate_status(ASTRA, "auto")["target_data_allowed"])


class AgentWiringTests(unittest.TestCase):
    """Exercise the agent's own gate methods, not a re-implementation of them."""

    @staticmethod
    def _agent(model: str, target_type: str, phase: str):
        from types import SimpleNamespace
        from agent import X19

        instance = X19.__new__(X19)   # skip the heavy __init__ (memory, MCP, learner)
        instance.ai = SimpleNamespace(model=model)
        instance.target_type = target_type
        instance._current_phase = phase
        return instance

    def test_blocks_exploitation_on_a_critical_model(self):
        instance = self._agent(ASTRA, "auto", "exploitation")
        self.assertFalse(instance._frontier_verdict().allowed)

    def test_blocks_the_other_phase_spelling(self):
        instance = self._agent(ASTRA, "auto", "exploit")
        self.assertFalse(instance._frontier_verdict().allowed)

    def test_allows_recon_on_a_critical_model(self):
        instance = self._agent(ASTRA, "auto", "recon")
        self.assertTrue(instance._frontier_verdict().allowed)

    def test_allows_exploitation_on_an_authorised_engagement(self):
        instance = self._agent(ASTRA, "authorized", "exploitation")
        self.assertTrue(instance._frontier_verdict().allowed)

    def test_allows_exploitation_on_an_ordinary_model(self):
        instance = self._agent(ORDINARY, "auto", "exploitation")
        self.assertTrue(instance._frontier_verdict().allowed)

    def test_explicit_phase_overrides_the_current_one(self):
        instance = self._agent(ASTRA, "auto", "recon")
        self.assertTrue(instance._frontier_verdict().allowed)
        self.assertFalse(instance._frontier_verdict("exploit").allowed)

    def test_missing_phase_attribute_defaults_to_observational(self):
        from types import SimpleNamespace
        from agent import X19

        instance = X19.__new__(X19)
        instance.ai = SimpleNamespace(model=ASTRA)
        instance.target_type = "auto"
        self.assertTrue(instance._frontier_verdict().allowed)

    def test_notice_is_printed_only_when_blocked(self):
        self.assertEqual(self._agent(ORDINARY, "auto", "exploit")._frontier_notice(), [])
        self.assertEqual(self._agent(ASTRA, "ctf", "exploit")._frontier_notice(), [])

        lines = self._agent(ASTRA, "auto", "recon")._frontier_notice()
        self.assertTrue(lines)
        self.assertIn("FRONTIER MODEL GATE", lines[0])
        self.assertTrue(any("recon" in line for line in lines))
        self.assertTrue(any(target in " ".join(lines) for target in AUTHORIZED_TYPES))


if __name__ == "__main__":
    unittest.main()
