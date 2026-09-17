# PentAGI-derived architecture integration

This document records implementation targets extracted from the current upstream PentAGI architecture without copying its code.

## Integrated concepts

- Execution supervision: detect repetitive tool calls and excessive exploration, then route context to a mentor/adviser layer.
- Hard per-agent execution limits with graceful termination near the limit.
- Optional task planning before specialist-agent work.
- Structured telemetry and distributed tracing around agent chains and tool execution.
- Persistent tool-call/result state alongside vector memory.
- Optional knowledge-graph enrichment for semantic relationships.
- Explicit runtime isolation as the preferred execution boundary.

## X19 mapping

| PentAGI concept | X19 implementation |
| --- | --- |
| repeating detector | `brain/assessment_telemetry.py` + existing anti-loop controls |
| mentor/adviser review | decision-quality / pre-execution guard |
| hard agent tool limits | command gateway counters + existing iteration controls |
| planning step | planner + team manager |
| OpenTelemetry/observability | trajectory telemetry and existing event system |
| PostgreSQL + pgvector state | existing state DB + Chroma/PGVector memory |
| Graphiti knowledge graph | existing `KnowledgeLayer`; graph integration remains optional |
| sandboxed Docker execution | `CommandGateway` + sandbox backend |

## Non-goals

This is not a PentAGI fork. Upstream-specific provider, Graphiti, or UI implementations are not copied. X19 retains its own policy engine, authorization model, autonomous loop, terminal UX, and verification pipeline.
