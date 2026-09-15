# X19 Security Memory V2

This memory layer merges recurring design patterns observed across modern offensive-security agents while keeping X19's existing engine intact.

## Canonical state

SQLite stores authoritative structured state. Vector/semantic retrieval is secondary and may provide relevant knowledge, but it cannot overwrite canonical facts or evidence.

## Memory types

- **Facts** — observed assets, services, endpoints, technologies and other world state.
- **Hypotheses** — explicit theories with confidence, basis and next test.
- **Evidence** — observations with provenance/receipts and links to hypotheses.
- **Attempts** — episodic records of actions, outcomes and failure attribution.
- **Dead ends** — closed branches with a reason so unchanged failures are not repeated.
- **Lessons** — reusable success/failure knowledge.
- **Priorities** — current investigation focus.
- **Relations** — graph edges such as `supports`, `tests`, `produced` and `explains`.
- **Checkpoints** — resumable mission state and cursor.

## Working-memory projection

The agent should consume a bounded `SecurityMemorySnapshot`, not the full transcript/database. `to_prompt()` preserves complete JSON records and never truncates serialized JSON in the middle of an object.

## Patterns merged from research

- PentestGPT: deterministic canonical state and bounded working sets.
- Neo: structured living working memory and specialist handoff compatibility.
- Shannon: resumable workspaces/checkpoints and proof-oriented evidence.
- Strix: attack-path context, agent graph relationships and finding evidence.
- PentAGI: separation of working, episodic and long-term knowledge plus graph relationships.
- LuaN1aoAgent: causal evidence→hypothesis→validation relationships, dynamic graph state and failure reflection.
- AutoPT: explicit state-machine/checkpoint thinking to avoid getting stuck in unbounded message history.
- VulnBot: task-graph decomposition and phase-aware coordination.
- PentestAgent: retrieval-backed security knowledge combined with specialized agents.
- TermiAgent: hierarchical memory activation so the model receives context near the current host/service/exploit branch.

This document describes memory architecture only; it does not authorize testing outside an explicitly authorized scope.
