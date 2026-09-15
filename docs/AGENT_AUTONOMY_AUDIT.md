# Agent Autonomy Audit — dynamic reasoning & critical-bug hunting

Second evidence-based audit (companion to `AGENT_UX_AUDIT.md`, which covered the
terminal UX). This one asks a different question: **is the agent's *brain*
dynamic — does it find problems by itself, and can it hunt critical bugs the
way production autonomous agents do?**

## 1. Research base (what "actually autonomous" looks like)

| Source | Core finding | Applied here as |
| --- | --- | --- |
| **Google Project Zero — Project Naptime / Big Sleep** (googleprojectzero.blogspot.com, June 2024; found the first real-world LLM-discovered 0-day in SQLite, Nov 2024) | 1. Vulnerability research is *iterative, hypothesis-driven*: formulate → design discriminating experiment → test → confirm/reject. 2. Grounding through tools — reasoning must be anchored in observable output, never vibes. 3. **Perfect verification**: structure tasks so success is unambiguous. 4. Hypothesis *ledgers* — the agent tracks its own open threads instead of re-deriving state every turn. | The decision schema gained a model-owned `hypotheses` ledger (below); finding verification stays deterministic + evidence-grounded. |
| **XBOW** (autonomous pentester, top-1 HackerOne US 2025) | 1. Fully autonomous: writes custom scripts per environment, no fixed playbook. 2. **Internal debate**: independent reviewer models evaluate every finding before reporting — kills false positives. 3. Chains small primitives into critical attack paths. | Adversarial second reviewer for critical/high findings; chaining guidance in the system prompt; tool-agnostic command parsing. |
| **12-factor agents** (humanlayer) | Own your control flow *in code*; own your context window; compact errors into context. | Guardrails (policy, anti-loop, scope) stay deterministic code; the *security knowledge* — what to test next — stays with the model. |

## 2. Audit: how dynamic was X19 already?

Verified by reading the loop (`agent.py` ~7,000 lines) and the `brain/` stack:

| Capability | Status before | Evidence |
| --- | --- | --- |
| Command generation | ✅ already LLM-driven | bootstrap/deep-recon hardcoded templates removed earlier (`_generate_planner_initial_recon`/`_parallel_deep_recon` are deprecated stubs returning empty) |
| Planner / world model | ✅ wired | `brain/planner.py`, `StrategistEngine`, `GoalTree` used each iteration |
| Finding verification | ✅ strong | 4-gate `_validate_finding` + `_llm_verify_finding` + stale-evidence check + HTTP cross-check, all on the main loop path |
| Hypothesis lifecycle | ⚠️ **system-owned** | `_hypotheses` dict tracked findings-derived categories only; **the model could not declare, test, confirm or reject a hypothesis through its decision** — the core Naptime loop was missing |
| Reasoning modules | ⚠️ **orphans** | `brain/hypothesis_engine.py` (MultiHypothesisEngine, 543 lines), `evidence_ranking.py`, `decision_engine.py`, `cognitive_runtime.py`, `coordinator.py` had **zero references in agent.py** — tested in isolation, never wired into the live loop |
| Prose command fallback | ❌ hardcoded allowlist | `_extract_prose_command` regex only accepted `nmap|curl|sqlmap|…` — a custom `katana`/fresh-script probe in backticks was silently dropped |
| Self-review of criticals | ❌ single judge | The model that *proposed* a critical finding was also its only LLM verifier (XBOW: use independent reviewers) |

## 3. Implemented (this phase)

1. **Model-owned research ledger (Naptime core).** The decision JSON now carries
   an optional `hypotheses` array — `{"action": "add|test|confirm|reject",
   "statement": …, "command": …, "expected_evidence": […], "reason": …}` —
   parsed by `brain/decision_parser.py` (dict → list, garbage → `None`) and fed
   to `MultiHypothesisEngine.apply_actions()`:
   - duplicate statements are ignored; a **rejected** statement re-opens only
     with a genuinely different probe (no re-running the falsified experiment);
   - the state machine (`NEW → TESTING → CONFIRMED/REJECTED/…`) is enforced,
     with an automatic `NEW → TESTING` hop for first-evidence confirms;
   - malformed actions never raise — each becomes a one-line transcript note.
   The ledger is rendered into every decision context
   (`render_context()`: open threads + next probe + expected evidence +
   confirmed/rejected history), so the agent's line of reasoning **persists
   across iterations** instead of being re-derived each turn. Per-target reset
   included. This also *wires the orphaned* `hypothesis_engine` module.
2. **Adversarial finding review (XBOW debate).** New `brain/finding_review.py`:
   after a critical/high finding passes the existing 4-gate + LLM-verify +
   HTTP-cross-check chain, one independent *hostile* reviewer (default stance:
   "this is a false positive") must agree. Disagreement demotes the finding and
   the loop keeps hunting; reviewer outage fails open (`unsure`); fast mode and
   lower severities skip the extra call (cost-bounded).
3. **Tool-agnostic prose extraction.** The hardcoded tool regex in both copies
   (`agent.py`, `brain/decision_parser.py`) is replaced by a shape heuristic
   (`_looks_like_shell_command`): any plausible `binary + args` line is
   accepted — custom scripts, freshly installed tools, python3 one-liners.
   Execution is still gated exclusively by the policy engine. `agent.py` now
   delegates to the shared parser (single source of truth).
4. **Deep-hunting guidance in the prompts** (LEAN_SYSTEM_PROMPT): the
   hypotheses-ledger workflow, falsifier discipline ("no falsification
   condition = a guess"), primitive-chaining ("two or three confirmed
   primitives chained = a critical candidate"), and depth-on-unusual-surface.
   Schema documented in all three prompt variants (LEAN, FAST, legacy).

## 4. Deliberately not done (and why)

- **Wiring `DecisionEngine`/`coordinator.py` wholesale**: they duplicate the
  live loop's selection role with different interfaces; ripping out the
  working planner for them is a rewrite-risk with no evidence of gain. The
  *hypothesis* module was wired because it added a missing capability.
- **Removing all heuristics from verification gates**: the exploit-indicator
  regexes in `_gate_security_impact` are deterministic verification (Naptime's
  "perfect verification"), not hardcoded behaviour — the model must still
  ground claims in real output. Code owns proof; the model owns ideas.
- **Guaranteeing "zero-days"**: no architecture can promise that. What this
  phase does is remove the structural blockers — fixed tool lists, no hypothesis
  ledger, single-judge verification — that kept discovery at the level of a
  checklist scanner. Discovery is now bounded by the model's reasoning, within
  deterministic policy/scope guardrails.

## 5. Verification

- 23 new tests (`tests/test_dynamic_reasoning.py`): ledger lifecycle
  (add/dedupe/confirm/reject/block-reopen), parser passthrough, tool-agnostic
  extraction, adversarial review (real/false-positive/outage/garbage), and
  source-level wiring guards. Full suite: **628 passed, 20 subtests**.
