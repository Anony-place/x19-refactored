# X19 Transformation Audit

**Date:** 2026-09-18  
**Branch:** x19-product-refactor  
**Base:** `main` at `f5cbc59471dae02e6b69558e97c14937580eadac`  
**Reference baseline:** `hermes-baseline` (unchanged)

## Result

The repository now presents X19 as the product identity while retaining the proven runtime architecture. The transformation is implemented by integrating X19 identity, orchestration, scope controls, and evidence-backed mission state into the existing agent loop, SOUL pipeline, delegation rail, TUI, CLI, memory, skills, sessions, gateway, approvals, and provider routing.

## Runtime seams changed

- `x19/identity/core.py` — X19 is the repository default; explicit config/env disable remains supported. Runtime SOUL no longer self-identifies as the upstream product.
- `hermes_cli/default_soul.py` — X19 SOUL is the default seed through the existing SOUL mechanism.
- `agent/system_prompt.py` — X19 identity is injected through the real per-turn identity pipeline while user SOUL customization remains supported.
- `agent/prompt_builder.py` — visible self-help guidance now describes X19, while internal compatibility names remain unchanged.
- `x19/orchestration/boss.py` — ready mission tasks dispatch through the existing `delegate_task` rail; scope is checked before dispatch; Operator pause/stop/kill controls reach live delegation controls.
- `x19/autonomous/team.py` — synthetic recon, fabricated findings, self-verification, and forced mission completion were removed. Missions remain active until real runtime results arrive.
- `hermes_cli/config_defaults.py` — `x19.enabled` defaults to true.
- `pyproject.toml` — `x19` is the primary CLI entry point; legacy `hermes` remains only as compatibility.
- `ui-tui/src/theme.ts`, `ui-tui/src/banner.ts`, `ui-tui/src/components/branding.tsx`, `ui-tui/src/entry.tsx` — user-facing TUI identity is X19 and the banner is minimal/operational.
- `hermes_cli/main.py`, `hermes_cli/main_tui_launch.py` — launcher/process identity and TUI resume output use X19.
- `README.md`, `docs/X19_PHASE3_STATUS.md` — product and phase documentation describe the actual evidence-backed runtime.
- `tests/x19/test_product_identity.py` — regression coverage for X19-default identity and anti-synthetic invariants.
- `package.json`, `x19/identity/__init__.py` — product-facing metadata/copy aligned to X19.

## Capability preservation

The existing agent loop, terminal execution, streaming, skills, memory, session persistence, delegation, gateway, provider routing, approval gates, and terminal cleanup remain in their original runtime modules. X19 calls the existing delegation engine rather than introducing a second agent framework.

## Evidence and safety invariants

No production path should claim reconnaissance, terminal output, findings, verification, or completion without real runtime evidence. Mission scope is checked before delegation. Human PAUSE/STOP/KILL/RESET controls remain authoritative. Candidate findings remain candidates until a real verification result promotes them.

## Knowledge and datasets

Existing X19 knowledge/dataset metadata documents source, license, provenance, safety, and PII/secrets filtering. Synthetic dataset examples are documented as synthetic and are not treated as runtime observations.

## Validation

Repository source and diff were re-inspected on the X19 branch after each critical runtime patch. GitHub code/status lookup currently reports no CI status contexts for head `85f55a3c2550923dfd6aea0517794ef3c9d19a35`; a local full test/build run was not possible in this environment because outbound GitHub network resolution failed.

## Not implemented / limitations

- The primary `x19` CLI entry point is added, but internal compatibility modules and environment variables retain upstream names where renaming would risk breaking the proven runtime.
- The branch does not claim automated live security execution by itself: the Boss bridge requires the live parent agent context and real authorization/scope, and mission completion depends on real delegated results.
- Full local pytest/npm/build execution remains unverified due the environment's repository network/DNS limitation.
