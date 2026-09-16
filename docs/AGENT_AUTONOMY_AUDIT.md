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

## 4b. Follow-up increment: chain hunting + variant analysis

Immediately after the ledger shipped, two more big-agent patterns were wired
in (still zero hardcoded behaviour — deterministic class-knowledge + soft
advisories, the hunt stays the model's):

5. **Chain opportunities in the loop (XBOW primitive chaining).**
   `ExploitChainEngine.hunting_guidance()` consumes the same compliance
   classifier the reports use and computes *near-miss* chains from the
   agent's own confirmed findings: "your confirmed SSTI typically enables
   remote_code_execution — confirming it lands a direct impact". Injected
   into every decision context as `CHAIN OPPORTUNITIES`. This turns the
   previously report-only chain engine into a live hunting compass.
6. **Variant analysis (Big Sleep).** Every confirmed finding now queues a
   soft advisory: enumerate sibling endpoints/parameters for the same bug
   class before pivoting — variants of a confirmed class are the
   highest-ROI probes. Delivered through the existing advisory queue
   (injected into the next decision prompt), never a forced gate.

## 4c. Increment: dynamic knowledge layer (real-time intel + custom corpus)

The user's directive: agent ko **custom knowledge layer** chahiye — prompt dump
nahi, **dynamic real-time data**, kuch bhi hardcoded nahi. Shipped as
`knowledge.py`:

- **Live sources** (runtime feeds, pluggable via `X19_INTEL_SOURCES`):
  CISA KEV catalog (actively-exploited + ransomware flags), NVD API 2.0
  keyword lookups (CVSS, description, public-PoC reference tags), FIRST EPSS
  (exploitation probability), local searchsploit (PoC titles). Optional
  `NVD_API_KEY` passthrough for rate limits.
- **Focused injection, not prompt stuffing**: `render_context()` correlates
  the world-model tech stack against the feeds — version-matched where the
  CVE description names the exact version, sorted KEV > EPSS > CVSS, hard
  caps (6 items / 2800 chars), and a FOCUS line telling the model to ignore
  intel that does not apply to the target's version. This replaces the
  decision loop's dependence on static knowledge; `CveMapper`'s legacy
  offline DB remains only as an offline fallback.
- **Real-time but resilient**: every source disk-caches under
  `~/.x19/cache/intel/` with TTLs (KEV 12h, NVD 24h, EPSS 6h); network
  failure falls back to stale cache (clearly labelled with its age); total
  failure degrades to an empty block. Never raises, never blocks the loop.
- **Custom layer (user's own brain)**: drop markdown/txt notes into
  `~/.x19/knowledge/` (or `X19_KNOWLEDGE_DIR`) — program policy, target
  notes, house playbooks. They are paragraph-chunked, hash-deduped and
  embedded into the vector store's `intel` collection; `recall()` surfaces
  them semantically in the decision context as CUSTOM KNOWLEDGE.
- Verified: 21 unit tests (parsing, TTL expiry, stale-fallback, disable
  switch, bounded rendering, corpus idempotency) + a live pipeline smoke
  (HTTP KEV+NVD feed → cache → version-matched Apache 2.4.49 intel block).

## 4d. Increment: OOB oracle — binary verification for blind vulnerability classes

Roadmap se sabse zyada value ka gap close kiya: X19 ka verification system
output-based tha, to **blind SSRF/XXE/blind-SQLi/OOB-RCE** ke true positives
bhi reject ho jaate the (response mein proof nahi hota). Ab interactsh
callbacks = binary oracle:

- **Redesigned poll path** (`_poll_oob_oracle`): callback ab durable evidence
  (`_oob_evidence` ring, 8) + live UI event (`◉ oob callback`) + honest
  **info-severity lead** hai — pehle wala bina-verification direct HIGH
  finding (false-positive machine) hata diya. Model real finding normal
  verified path se file karta hai, callback line ko evidence ke roop mein
  quote karte hue.
- **Deterministic correlation**: jis TESTING hypothesis ke probe mein exact
  canary tha, wo callback se auto-CONFIRM ho jata hai (ledger + oracle wired).
- **Gate integration**: `[OOB INTERACTION]` line ab exploit-indicator hai aur
  binary oracle ke roop mein critical-claim ke extra-context requirement se
  exempt — evidence_context mein OOB lines hamesha streams ke saath jaate
  hain.
- **Model ko canary ab dikhta hai**: `OOB ORACLE ACTIVE — canary host: …`
  block decision context mein — custom blind probes (curl/python3/XXE DTD)
  kar sakta hai, sirf nuclei/sqlmap auto-inject nahi. No-interactsh
  environment mein honest "callbacks NOT monitored" block (koi jhootha
  promise nahi).
- Prompts (LEAN + fast) document the oracle workflow; 11 new tests
  (`tests/test_oob_oracle.py`).

## 4e. Increment: hierarchical bug-hunting team (boss → managers → workers)

User ka directive: X19 ek single agent nahi — poora team ho jo fast aur
best-approach se kaam kare, sab boss ko report kare. Shipped as
`brain/team.py` (HPTSA/PentAGI organisational pattern):

- **MissionDirector (boss)**: dynamic lane decomposition (boss-model LLM
  planning from the live world state, deterministic surface-derived
  fallback), probe budget, aur verified findings ka review — severity
  rollup + exploit-chain summary. Boss reviews; boss never bends
  verification.
- **WorkstreamManager + ProbeWorker (managers/employees)**: per-lane probe
  queues + worker pools. Workers sirf injected executor (X19 ka policy-gated
  gateway) chalate hain — raw subprocess kabhi nahi; scope, rate limits,
  command gateway sab inherit. Workers raw evidence laute hain (rc +
  excerpt + duration), findings nahi — "worker report alone is never
  proof" (prompt-documented rule).
- **Loop integration**: decision JSON ka `team` field (spawn/assign/retire),
  `_team_tick()` har iteration (budget reset, lazy planning once surface
  known, harvest, review), TEAM STATUS / BOSS REVIEW / LANE REPORTS context
  blocks, `♛ team` live UI events, per-target reset + loop-end shutdown.
- **Dynamic, not hardcoded**: lane naam/mission/workers boss model se aate
  hain — target ke exposed surface se; fallback bhi world-model-derived.
  Knobs: `X19_TEAM_DISABLE`, `X19_TEAM_MAX_LANES` (3), `X19_TEAM_WORKERS`
  (2/lane), `X19_TEAM_PROBES_PER_ITER` (6).
- 17 tests (`tests/test_team.py`); workers live smoke via real
  CommandGateway.

## 4f. Increment: parallel research trajectories (Naptime sampling on the ledger)

Roadmap ka top item close: ledger ki pre-registered hypotheses ab **parallel
chalti hain**, sirf sequential nahi —

- Dispatch: har iteration, TESTING/NEW hypotheses jinhone **probe command +
  expected evidence** pre-register kiya hai, team workers pe auto-dispatch
  hote hain (`X19_TEAM_TRAJECTORIES`, default 2; shared probe budget).
  Main loop ka next_command judgment ke liye bachta hai; breadth team pe.
- Evaluation: worker report vs hypothesis ka **apna pre-registered success
  criterion** — match → auto-confirm (model ne khud falsifier define kiya
  tha — pre-registration contract). Miss → boss model ko note (refine ya
  reject kare). Short evidence tokens sirf word-boundary match pe confirm
  karte hain (`49` ≠ `1492`).
- Findings ka verification path unchanged — confirm hypothesis ≠ reported
  finding; gates + adversarial review phir bhi zaroori.
- 13 tests (`tests/test_trajectories.py`).

## 4g. Increment: frontier escalation + usage accounting

Roadmap items 2 (frontier gating) aur 9 (cost transparency) close:

- **Escalation chain** (`brain/escalation.py`): `X19_ESCALATE="provider/model"`
  — hard steps (critical/high focus-finding deep-dive ≥ depth 2, high-impact
  open hypothesis ≥ 0.8, flail streak ≥ 3, no-progress streak ≥ 3) decision
  call ko stronger model pe bhejte hain. Default off (accounts/keys
  user-specific — kuch hardcoded nahi).
- **Gate-respecting**: critical-tier model pe escalation exploitation phase
  mein `brain.frontier_gate` verdict se guzarti hai — unauthorised engagement
  pe fail-closed. Standard-tier models ungated.
- **Cooldown** (`X19_ESCALATE_EVERY`, default 4 decisions) + one-shot backend
  via naya `providers.build_backend` (FailoverRouter._backend_for ab isi pe
  delegate karta hai).
- **Usage accounting**: har decision call session usage mein account hota hai
  (calls/chars/secs/escalations); ribbon dikhata hai `N calls ~Tk tok`, aur
  `~$X` jab operator apni blended rate `X19_PRICE_PER_MTOK` se de.
- 17 tests (`tests/test_escalation.py`).

## 4h. Increment: fleet mode (multi-target supervisor)

Roadmap ka aakhri bada item close — X19 ab ek process mein kai targets chala
sakta hai (XBOW scale pattern):

- **FleetSupervisor** (`brain/fleet.py`): bounded worker pool
  (`X19_FLEET_CONCURRENCY`, default 2, max 8); har unit ek poora X19 agent
  hai apne session ke saath — scope gate, policy engine, verification gates
  aur team org per-unit inherit hote hain. Supervisor sirf fleet-level cheezein
  add karta hai.
- **Failure isolation**: ek target ka crash baaki units ko kabhi nahi chhoota;
  lifecycle queued → running → done/failed/stopped.
- **Cooperative control**: `stop(target)` / `stop_all()` agent ke stop flag se.
- **Fleet summary**: severity rollup across targets + **shared tech stacks**
  (same stack ≥2 targets pe → intel aur confirmed hypotheses transfer).
- **Entry points**: headless `x19 fleet -t t1,t2,t3 --max N` (run.py routing,
  nonzero exit agar koi unit fail ho) + workspace `/fleet t1, t2` /
  `/fleet status` / `/fleet stop` (background task, ribbon note live).
- 15 tests (`tests/test_fleet.py`).

## 5. Roadmap — what still separates X19 from big-agent caliber

Prioritised by expected impact on real bug-hunting throughput:

1. **Independent parallel trajectories** (Naptime's sampling strategy): run
   the top-N competing hypotheses as separate short research threads and let
   verification pick winners, instead of one sequential trajectory. Needs the
   loop to become a dispatcher over per-hypothesis micro-sessions.
2. ~~**Frontier-model gating for hard steps**~~ → ✅ shipped (§4g:
   `X19_ESCALATE` chain, gate-respecting, cooldown-bounded).
3. ~~**Fleet mode**~~ → ✅ shipped (§4h: `FleetSupervisor`, bounded pool,
   failure isolation, shared-stack correlation, `/fleet` + `x19 fleet`).
4. **Blind-vuln OOB correlation**: `attacks.get_oob/oob_inject` exist; wiring
   OOB callback polling into hypothesis confirmation would close the blind
   SSRF/SQLi evidence gap.

## 6. Verification

- 23 new tests (`tests/test_dynamic_reasoning.py`): ledger lifecycle
  (add/dedupe/confirm/reject/block-reopen), parser passthrough, tool-agnostic
  extraction, adversarial review (real/false-positive/outage/garbage), and
  source-level wiring guards.
- 9 more (`tests/test_chain_hunting.py`): near-miss guidance (single-hop,
  two-hop, already-complete, info-only, limit), classifier parity with
  reports, and wiring guards.
- Knowledge layer: 21 (`tests/test_knowledge_layer.py`); OOB oracle: 11
  (`tests/test_oob_oracle.py`); team org: 17 (`tests/test_team.py`);
  trajectories: 13 (`tests/test_trajectories.py`); escalation+usage: 17
  (`tests/test_escalation.py`); fleet: 15 (`tests/test_fleet.py`);
  full-loop integration: 1 (`tests/test_integration_loop.py`) — ek real
  `_autonomous_loop_impl` run jismein team tick, parallel trajectory
  dispatch → policy-gateway execution → pre-registered auto-confirm,
  ledger/OOB/lanes context blocks aur usage accounting sab ek saath
  composed verify hote hain. Full suite: **732 passed, 20 subtests**.
