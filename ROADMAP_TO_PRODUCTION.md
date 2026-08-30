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

1. Wire `CriticEngine` and `StrategistEngine` directly into `agent.py`'s `_autonomous_loop_impl`.
2. Migrate `ToolExecutor` inside `tools.py` to use `execution/command_gateway.py` exclusively.
3. Replace hardcoded templates in `brain/planner.py` with LLM query calls passing `WorldModel` context.
