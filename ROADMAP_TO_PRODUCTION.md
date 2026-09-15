# X19: Roadmap to Production-Grade Autonomous Offensive Security Agent

This document outlines the engineering blueprint to evolve **X19** from an advanced research prototype into a **production-grade enterprise autonomous pentesting platform**.

---

## Architecture Overview: Current vs. Target

```
[ Current Prototype Architecture ]
┌─────────────────┐       ┌─────────────────┐       ┌──────────────────┐
│   Agent Loop    │──────▶│   LLM Planner   │──────▶│  Local Subprocess│
│   (agent.py)    │       │  (planner.py)   │       │   (tools.py)     │
└─────────────────┘       └─────────────────┘       └──────────────────┘

[ Production Architecture ]
┌────────────────────────────────────────────────────────────────────────┐
│                          X19 Cognitive Brain                           │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐  │
│  │ Evidence Ranking │  │ Hypothesis Engine│  │ Attack Graph Engine  │  │
│  │ (Multi-dim score)│  │ (Competing hyps) │  │ (Path optimization)  │  │
│  └────────┬─────────┘  └────────┬─────────┘  └──────────┬───────────┘  │
└───────────┼─────────────────────┼───────────────────────┼──────────────┘
            │                     │                       │
            ▼                     ▼                       ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      State-Aware Planner & Critic                      │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐  │
│  │  Critic Engine   │  │  Strategist Eng. │  │   Strategy Library   │  │
│  │(Numeric Penalty) │  │ (Dynamic Goals)  │  │  (Cross-Session DB)  │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────────┘  │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│               Isolated Execution Gateway (Containerized)              │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐  │
│  │ Docker/gVisor    │  │ Hard Scope Guard │  │ Real-time Telemetry  │  │
│  │ Sandbox Isolation│  │ (IP/CIDR/Domain) │  │ Stream & Audit Log   │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Key Pillars for Production Readiness

### Pillar 1: Full Loop Integration of Cognitive Engines
* **Current State**: `CriticEngine`, `StrategistEngine`, `StrategyLibrary`, `EvidenceRanking`, `HypothesisEngine`, and `AttackGraph` are implemented as modular units in `brain/`, but `agent.py` still relies partially on heuristic fallbacks.
* **Target Changes**:
  1. In `agent.py`: Replace legacy goal selection (`GoalTree.select_active_node`) with `StrategistEngine.analyze_attack_graph()`.
  2. In `agent.py`: Call `CriticEngine.criticize_failure()` on tool errors to directly decay entity confidence in `WorldModel`.
  3. Query `StrategyLibrary.recommend_strategies()` on new target initialization to seed proven attack chains.

### Pillar 2: LLM-Driven Dynamic Hypothesis Generation
* **Current State**: Some hypotheses rely on static templates (`SERVICE_ATTACKS` in `constants.py`).
* **Target Changes**:
  1. Update `brain/hypothesis_engine.py` to prompt the LLM directly with current `WorldModel` entities.
  2. Require explicit confidence, information gain, execution cost, and risk scores for every generated hypothesis.
  3. Enforce strict re-testing limits so rejected or dead hypotheses are never re-triggered without new evidence.

### Pillar 3: Containerized Execution & Real-time Streaming
* **Current State**: `ToolExecutor` runs shell commands locally via Python `subprocess.run()`.
* **Target Changes**:
  1. Wrap `CommandGateway` (`execution/command_gateway.py`) to execute commands inside isolated Docker / gVisor sandboxes.
  2. Implement stream-parsing (`subprocess.Popen` with async stdout/stderr streaming) so `TargetModel` updates live during long scans (e.g. `nmap` or `gobuster`).
  3. Enforce strict resource limits (CPU, Memory, IOPS, Network egress filtering).

### Pillar 4: Hard Scope Enforcement & Policy Engine
* **Current State**: Permissive policy until scope enforcement is manually enabled in config.
* **Target Changes**:
  1. Make `PolicyEngine` (`execution/policy_engine.py`) mandatory for ALL commands.
  2. Implement strict subnet/CIDR and wildcard domain validation before command resolution.
  3. Automatically block destructive commands, unauthorized port ranges, and out-of-scope pivots at the gateway layer.

### Pillar 5: Persistent Knowledge Graph & Cross-Session Memory
* **Current State**: Memory utilizes local ChromaDB or json stores per target.
* **Target Changes**:
  1. Persist the `AttackGraph` (`brain/attack_graph.py`) to a graph database (Neo4j or persistent SQLite/NetworkX JSON).
  2. Store vectorized target signatures and successful exploitation techniques in Chroma vector store.
  3. Implement cross-engagement learning so lessons from Target A immediately benefit attacks on Target B with similar tech stacks.

### Pillar 6: Automated CI/CD Benchmarking & Vulnerability Verification
* **Current State**: Unit test suite tests isolated components.
* **Target Changes**:
  1. Add automated integration tests against vulnerable docker targets (e.g., OWASP Juice Shop, DVWA, Metasploitable).
  2. Require 4-gate verification (`unexpected_behavior`, `security_impact`, `reproducibility`, `evidence`) for ALL findings before inclusion in final reports.
  3. Track Cognitive Score metrics in CI/CD pipeline to prevent regressions in autonomous reasoning quality.

---

## Immediate Next Steps for Developers

Updated after the autonomy pass (see `AUTONOMY_CHANGES.md`). Items 1-2 of the
previous list are done or obsolete; the ordering below is now about containment
rather than about wiring more reasoning into a loop that was refusing to act.

1. **Containment before capability.** `ToolExecutor` executes arbitrary shell via
   `subprocess.run(shell=True)` as the current user, guarded by a regex denylist.
   Move execution behind a container / gVisor / network namespace so scope is
   enforced by the OS. Install `execution/scope_guard.py`'s socket-level check on
   that path — it currently only covers `brain/coordinator.py` and the native
   modules, all of which construct it with `enforce=False`.
2. **Retire the self-modifying upgrader or fence it.** `x19upgrader.py`
   `import_to_main()` copies files over the live source tree; `self_improve.py`
   patches source by string replacement behind a string-matching safety check.
   Neither should be reachable from a box that holds engagement data.
3. **`Planner` heuristics are still a second voice.** `brain/planner.py`
   `METHODOLOGIES` and `constants.py` `SERVICE_ATTACKS` are static playbooks with
   hardcoded shell strings and confidence numbers. Keep them as *proposals the
   model can accept or reject*; today they take over during provider fallback.
4. Remove `datasets/` from git history (49 MB of copyrighted books).
5. `agent.py` is still ~6,900 lines. The soft gates were converted to advisories
   in place; they belong in a `brain/guardrails.py` that can be tested without an
   `X19`.

Done in the autonomy pass, so nobody re-does it: fabricated bootstrap ports and
`www.` subdomains removed; `host:port` targets no longer lose their port;
`PolicyEngine` no longer mistakes a User-Agent version string for a destination
(and now catches destinations inside query strings); the destructive denylist
checks every statement instead of the first; soft gates inform instead of
refusing; `tool_distributions.py` and `brain/decision_engine.py` deleted.
