# X19 Migration: Script Removal & True Autonomy Enforcer (Revised)

## 0. Source-of-truth command pipeline (no direct execution)
- [ ] Remove/disable `X19._bootstrap_recon()` hardcoded bootstrap burst
- [ ] Remove/disable `X19._parallel_deep_recon()` hardcoded parallel recon launcher
- [ ] Remove/disable `X19._bug_bounty_bootstrap()` hands-free recon burst
- [ ] Remove CTF flag-hunting pipeline block inside `X19._autonomous_loop_impl()`

## 1. Transform bootstrap into Planner-generated tasks
- [ ] Update `brain/planner.py` methodologies/templates so bootstrap probes are represented as recon tools/steps for first iteration

## 2. Graceful degradation on AI provider failure
- [ ] Refactor `_autonomous_fallback_decision()` to implement: retry (+60s) -> switch provider -> cooldown -> simplified system prompt -> fail mission if all providers fail
- [ ] Purge canned/mock reasoning from mission `local_decision()` and any other “fake thinking” branches

## 3. Expand reflection engine
- [ ] Implement richer `_self_reflect()` and inject reflection into LLM context via `_build_context()`

## 4. Enrich world model telemetry
- [ ] Add fields to `brain/world_model.py` (confidence, provenance, completed_checks, remaining_unknowns, candidate_attack_paths)
- [ ] Update `X19._extract_to_model()` to populate structured telemetry

## 5. Explicit reasoning layer + policy validation
- [ ] Update `utils.decision_system_prompt()` to enforce two-pass JSON with deliberation/hypothesis/expected evidence/command_request
- [ ] Extend `execution.CommandRequest` with hypothesis mapping fields
- [ ] Extend `execution.PolicyEngine.evaluate()` to verify hypothesis<->expected evidence<->command mapping before execution

## Verification strategy (required after refactor)
- [ ] `python x19debugger.py check`
- [ ] `python -m unittest discover -s tests`
- [ ] Smoke: `python run.py -t 127.0.0.1` (confirm first recon is planner-generated and routes through command gateway/policy)
