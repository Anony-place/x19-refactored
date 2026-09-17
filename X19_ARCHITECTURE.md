# X19 Production Architecture & Cognition Map — 2026 Refresh

> Seeded from 2026 top-10 survey (XBOW/Big Sleep/Atlantis/Shannon/NodeZero/PentAGI/CAI/HexStrike/Strix/HPTSA + NodeZero $2B, PentAGI OTEL, HexStrike MCP). X19 copies *patterns & guarantees*, never hardcoded exploit recipes. All execution stays behind authorization/policy.

---

## 1. System Architecture Diagram (2026 target)

```
                         ┌─────────────────────────────┐
                         │     User / Terminal / CLI   │
                         │  (ui/fullscreen_workspace)  │
                         │  status+telemetry+activity  │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              X19 AGENT CORE (agent.py)                               │
│  decision loop: Observe → Hypothesize → Test → Verify → Learn (evidence-driven)      │
│                                                                                      │
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌───────────────────────┐       │
│  │  WorldModel Graph    │─▶│ MultiHypothesisEngine│─▶│ StrategistEngine      │       │
│  │  world_model.py      │  │ hypothesis_engine.py │  │ strategist_engine.py  │       │
│  │  Hosts/Services/EP/  │  │ NEW→TESTING→CONFIRM  │  │ AttackGraph path opt  │       │
│  │  Creds/Tech/Vulns    │  │ Priority = 0.25C+0.35│  │ StrategyLibrary       │       │
│  └──────────┬───────────┘  │  IG+0.20(1-Cost)+    │  └───────────┬───────────┘       │
│             │              │  0.20(1-Risk)        │              │                   │
│             │              └──────────┬───────────┘              ▼                   │
│  ┌──────────▼───────────┐  ┌──────────▼───────────┐  ┌───────────────────────┐       │
│  │   CriticEngine       │◀─│ 4-Gate Verification  │◀─│ Planner+DecisionGuard │       │
│  │  critic_engine.py    │  │ + FindingReview      │  │ planner.py +          │       │
│  │  failure taxonomy    │  │ (Obs→Conf) + PoV     │  │ decision_guard.py     │       │
│  │  penalty decay       │  │ OOB oracle, variant  │  │ ATLAS+quality guard   │       │
│  └──────────────────────┘  └──────────────────────┘  └───────────────────────┘       │
│                                                                                      │
│  ┌────────────────────────────────────────────────────────────────────────┐         │
│  │ Team Org (brain/team.py): MissionDirector → WorkstreamManager →      │         │
│  │ ProbeWorker (policy-gated executor), parallel trajectories (Naptime), │         │
│  │ Fleet (brain/fleet.py) bounded 2-8 units, shared-stack correlation    │         │
│  └────────────────────────────────────────────────────────────────────────┘         │
└─────────────────────────────────────────┬──────────────────────────────────────────┘
                                          │
                                          ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        COGNITIVE MEMORY & OBSERVABILITY                                │
│  ┌──────────────────┐  ┌──────────────────┐  ┌────────────────────────────┐          │
│  │ KnowledgeLayer   │  │ Episodic Memory  │  │  Observability (runtime/)  │          │
│  │ + Graphiti/Neo4j │←▶│ learning/        │→ │  OTEL→VictoriaMetrics/     │          │
│  │ pgvector/Chroma  │  │ episodic_memory  │  │  Jaeger/Loki/Grafana +     │          │
│  │ Working+Vector+  │  │ failure-memory   │  │  Langfuse/ClickHouse       │          │
│  │ Episodic 3-layer │  │ correlated       │  │  attack credits + treemap  │          │
│  └──────────────────┘  └──────────────────┘  └────────────────────────────┘          │
│                      White-box Correlator (brain/whitebox_correlator.py)             │
│                      source ↔ dynamic (Shannon 96% pattern)  — optional               │
└─────────────────────────────────────────┬──────────────────────────────────────────┘
                                          │
                                          ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                      ISOLATED EXECUTION GATEWAY (mandatory)                            │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────────┐            │
│  │  CommandGateway  │→ │   ScopeGuard     │→ │ PolicyEngine + Attack    │            │
│  │ command_gateway  │  │ scope_guard.py   │  │ Credits budget guard     │            │
│  │  + MCP Gateway   │  │ OS/socket-level  │  │ policy_engine.py         │            │
│  │ mcp_gateway.py   │  │ signed-scope     │  │ max_seconds/commands/    │            │
│  │ 150+ tools MCP   │  │ no regex bypass  │  │ llm_calls hard limits    │            │
│  └────────┬─────────┘  └──────────────────┘  └──────────────────────────┘            │
│           │                                                                            │
│  ┌────────▼─────────┐  ┌──────────────────┐  ┌──────────────────────────┐            │
│  │ SandboxExecutor  │  │ Native Engines   │  │ Browser+Proxy Env         │            │
│  │ sandbox.py Docker│  │ native_net/fuzzer│  │ (BrowserAutomation +      │            │
│  │ /gVisor + Kali   │  │ /vuln (15 fams)  │  │  HTTP proxy manip)        │            │
│  │ image x19-sandbox│  │ coverage+c2      │  │  Strix-â€pattern          │            │
│  └──────────────────┘  └──────────────────┘  └──────────────────────────┘            │
└─────────────────────────────────────────┬──────────────────────────────────────────┘
                                          │
                                          ▼
                          ┌───────────────────────────────┐
                          │ Target System / Network Layer │
                          │ (internal/external/cloud/AD)  │
                          └───────────────────────────────┘
```

---

## 2. Key Cognitive Subsystems (2026)

### A. WorldModel Knowledge Graph (`brain/world_model.py` + `brain/attack_graph.py`)
- Hosts/Services/Endpoints/Params/Tech/ Creds/Vulns + typed edges (HOST_HAS_SERVICE, SERVICE_SERVES_ENDPOINT, ... FINDING_CONFIRMS, HYPOTHESIS_TESTS).
- **2026 delta:** add AD/cloud identity nodes (NodeZero pattern), persist to pgvector/Neo4j (PentAGI), correlate white-box source edges when repo given.
- Provenance per transition, path caching, evidence → confidence, not LLM trust.

### B. MultiHypothesisEngine (`brain/hypothesis_engine.py`)
- NEW→TESTING→CONFIRMED/REJECTED/STALE/DEAD, priority = 0.25C +0.35 IG+0.20(1-Cost)+0.20(1-Risk), attempt_count, falsifiers, pre-registration contract.
- **2026 addition:** `brain/attack_credits.py` — per-chain attack credits (XBOW), N-version trajectories dispatched via team workers, variant sweep advisory stays.

### C. CriticEngine & Failure Taxonomy (`brain/critic_engine.py`)
- Multi-class (Auth/Scope/RateLimit/InvalidHyp), soft penalty → numeric decay → hard block after 3, saturation detection.
- Wired to StrategyLibrary re-ranking and Team budget.

### D. Verification: 4-Gate + PoV + OOB + Adversarial Review
- `agent.py::_validate_finding` 4-gate (unexpected_behavior, security_impact, reproducibility, evidence) + stale-evidence + HTTP cross-check + `[OOB INTERACTION]` oracle (`_poll_oob_oracle` durable 8-ring + hypothesis auto-confirm).
- `brain/finding_review.py` hostile second reviewer mandatory for critical/high.
- **2026 add:** `brain/pov_validator.py` — on chain confirm, team dispatches combined exploit probe, re-run as binary oracle, 1-click Verify after fix (XBOW/NodeZero).

### E. Team Org & Fleet (`brain/team.py`, `brain/fleet.py`, `brain/task_queue.py`, `brain/coordinator.py`)
- MissionDirector (LLM-planned lanes from live world state, fallback surface-derived), WorkstreamManager per lane bounded probe budget (6/iter), ProbeWorker via policy-gated executor (raw evidence only, “worker ≠ proof”).
- Parallel trajectories pre-registered hypotheses auto-dispatched; fleet bounded pool 2-8, failure isolation, shared-stack correlation.
- **2026 delta:** narrow per-worker context (HPTSA), safety SLLM per-action review (XBOW), signed-scope propagation to fleet units.

### F. Memory: Vector + Working + Episodic + Knowledge Graph
- Chroma vector + session + failure-memory today.
- **2026 add `learning/episodic_memory.py` + Graphiti/Neo4j bridge (PentAGI):** per-target run history → semantic recall, failure-memory ↔ vector correlation, compounding across engagements.

### G. Planning & Guards
- `brain/planner.py` + `brain/decision_guard.py` (ATLAS tagging `brain/atlas.py`, `brain/decision_guard.py`) + `brain/evidence_ranking.py` multi-dim + `brain/strategist_engine.py`.
- Deterministic orchestration principle: code owns control flow, LLM is reasoning node (Atlantis tiers, CHECKMATE PDDL).

---

## 3. Execution Boundary (P0/P1 hardening — 2026)

### CommandGateway (`execution/command_gateway.py`)
- Mandatory entry, verdict before run, budget enforcement (commands/llm_calls), started/exit logs.
- **2026 hardening:** wire `ScopeGuard` socket-level check *on the gateway* (not only coordinator), make sandbox mandatory (no silent host fallback for network), signed-scope artifact + replay-verified evidence (Plexicus), integrate `execution/mcp_gateway.py`.

### Sandbox (`execution/sandbox.py`)
- Docker `x19-sandbox:latest`, network=none default, read-only FS, cap-drop ALL, tmpfs 256m, workspace rw only, pids 256, sticky unavailable detection (125 markers).
- **2026:** per-agent/per-tool containers, gVisor option, Kali 20+ → 150+ tools via MCP (HexStrike 150, Penligent 200).

### MCP Gateway NEW (`execution/mcp_gateway.py` — HexStrike pattern)
- FastMCP server bridging Claude/GPT/Copilot → 150+ tools (25 net, 40 web, 20 cloud, 25 binary, 20 OSINT) as standardized functions, intent→execution translation, retry/resilience, smart caching, compact mode for CI/CD.

### Native Engines + Browser/Proxy Env
- `execution/native_net.py`, `native_fuzzer.py`, `native_vuln.py` 15 families (CORS/SSTI/JWT/SSRF heuristic, etc.), `parsers/` (nmap/ffuf/gobuster/httpx).
- **2026 add:** HTTP proxy manipulation + browser automation + Python exploit env (Strix), stateful workflow testing (BOLA/IDOR role diff).

### Observability NEW (`runtime/observability.py` — PentAGI pattern)
- OTEL-style spans → `events.py` + file + optional Grafana/Jaeger/Loki/Grafana + Langfuse/ClickHouse/Redis/MinIO, attack-credit treemap per endpoint tested (XBOW), full audit (every packet/log).

### White-box Correlator NEW (`brain/whitebox_correlator.py` — Shannon 96%)
- Optional repo/API-spec intake → static analysis edges → correlate with dynamic findings → exact source location + PoC exploit per vuln.

---

## 4. Weakness → Fix Mapping (from parity matrix)

| Weakness (2026) | Root | Fix (code) | Status |
| --- | --- | --- | --- |
| Scope bypassable regex, not on main loop | PolicyEngine textual only, ScopeGuard only in coordinator | wire ScopeGuard into CommandGateway, signed-scope | P0 — patch below |
| Silent host fallback undoes sandbox | `auto` degrades silently | make sandbox fail-closed for network, log + require operator opt-out | P0 |
| Chain PoV re-run missing (XBOW 48-step) | chains report without re-execution | `brain/pov_validator.py` + team probe | P1 |
| MCP 150+ tools missing | 70 binaries, no server | `execution/mcp_gateway.py` | P1 |
| Episodic memory thin | failure-memory not correlated | `learning/episodic_memory.py` + Graphiti | P2 |
| White-box correlation missing | black-box only | `brain/whitebox_correlator.py` | P2 |
| Observability thin (no OTEL) | events.py only | `runtime/observability.py` | P2 |
| Attack credits missing | only iter cap | `brain/attack_credits.py` + treemap | P2 |
| Per-agent narrow context missing | shared decision context | narrow context per lane worker | P3 |
| AD/cloud graph missing | hosts/services only | extend WorldModel nodes | P3 |
| Browser/proxy env not loop-integrated | BrowserAutomation exists standalone | loop-integrate proxy manipulation | P3 |

---

## 5. Guarantees (non-negotiable)

1. **Evidence before finding:** 4-gate + adversarial review + OOB/PoV oracle — LLM opinion never proof; worker evidence alone never proof; chain without PoV re-run = advisory not finding.
2. **Deterministic control flow:** retry, scope, budget, verification in code, not in prompt. CHECKMATE 20% win validates this.
3. **Scope is OS-enforced:** regex is advisory; socket/network namespace is boundary. Signed-scope replay-verified.
4. **Borrow patterns, not payloads:** copy XBOW validator, Big Sleep oracle, Atlantis tiers, PentAGI observability, HexStrike MCP — never hardcode exploit strings.
5. **Terminal-first operator surface:** target/provider/status/credits, transcript, command line, activity strip, treemap — no nested panels.
