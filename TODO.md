# X19 Migration: Script Removal & True Autonomy Enforcer (Revised)

> Re-audited against `agent.py` @ 3c1e93a + the reasoning-gate changes on this
> branch. Most of the original list was **already implemented but never
> checked off** — that staleness was the actual reason "nothing feels fully
> working". Statuses below reflect the code, not the aspiration.

## 0. Source-of-truth command pipeline (no direct execution)
- [x] `X19._bootstrap_recon()` removed — no def, no call sites anywhere
- [x] `X19._parallel_deep_recon()` no longer invoked; still a dead def (agent.py:1642)
- [ ] `X19._bug_bounty_bootstrap()` still a hardcoded hands-free recon burst
      — live at `agent.py:1769`, gated on `(bug_bounty_mode or fast_mode) and CONFIG.AUTO_BOOTSTRAP`.
      Removal needs planner parity: `brain/planner.py` must emit the equivalent
      first-iteration probes (`AUTO_BOOTSTRAP=0` is the current escape hatch).
- [x] CTF flag-hunting pipeline block gone from `_autonomous_loop_impl()` —
      banner + comment only, "no commands are generated here"

## 1. Transform bootstrap into Planner-generated tasks
- [x] `_queue_autonomy_tasks("assessment", "session start autonomy seeding")` seeds
      the task queue at session start — this is the planner-generated path
      `_bug_bounty_bootstrap` still short-circuits

## 2. Graceful degradation on AI provider failure
- [x] `_autonomous_fallback_decision()` implements the full ladder:
      retry +60s → `_switch_provider()` → cooldown(`_rate_limit_backoff`) →
      simplified prompt → extended timeout → **`_mission_failed` marker instead
      of fabricated reasoning** (agent.py:4348)
- [x] Canned `MissionManager.local_decision()` has no callers — dead code, not
      a live "fake thinking" branch. `_autonomous_fallback_decision` never
      synthesizes a decision locally.

## 3. Expand reflection engine
- [ ] `_self_reflect()` (agent.py:5881) is still rule-based; `_build_context()`
      injection not verified. Open.

## 4. Enrich world model telemetry
- [x] `brain/world_model.py` has `confidence`, `provenance`, `completed_checks`,
      `remaining_unknowns`, `candidate_attack_paths`
- [ ] `_extract_to_model_impl()` (agent.py:839) populates partially. Verify + finish.

## 5. Explicit reasoning layer + policy validation
- [x] `execution/command_request.py` carries `hypothesis_id`, `hypothesis`,
      `expected_evidence`, `evidence_required`
- [x] **`PolicyEngine._evaluate_reasoning()` now verifies the
      hypothesis ↔ expected-evidence ↔ command mapping before execution**
      (rule `hypothesis_mapping` / `evidence_claim`), and
      `CommandGateway.run_shell()` forwards the metadata instead of dropping it
- [ ] `utils.decision_system_prompt()` still does not *demand* two-pass JSON with
      deliberation — the policy now rejects unjustified commands, but the prompt
      doesn't yet tell the model to supply the mapping. Open, and it is the one
      that changes model behaviour rather than merely enforcing it.

## 6. Local / self-hosted inference (added on this branch)
- [x] `custom_openai` provider: any OpenAI-compatible endpoint via
      `X19_AI_BASE_URL` (+ optional `X19_AI_API_KEY`, `X19_AI_MODEL`).
      Deliberately **not** in `PROVIDER_PRIORITY` — it must never hijack a
      cloud-configured install — and never wrapped in `FailoverRouter`, so an
      operator who chose a loopback endpoint can never have engagement data
      silently sent to a cloud provider. A missing/malformed `X19_AI_BASE_URL`
      raises instead of falling through.

## Verification strategy (required after refactor)
- [x] `python x19debugger.py check` → syntax OK, 72 imports, 0 issues
- [x] `python -m unittest discover -s tests` → **528 tests, OK** (521 + 7 new)
- [ ] Smoke `python run.py -t 127.0.0.1` — still blocked by design until a
      provider is configured; run it once `custom_openai` or a cloud key is set,
      and confirm the first recon command arrives through the planner + gateway
      with a non-empty `hypothesis` field.
