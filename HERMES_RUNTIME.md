# X19 Hermes-Inspired Runtime

X19 already has a security-specific cognitive core: world model, hypotheses,
planner, attack graph, swarm agents, verification, scope enforcement and
self-adaptation. This layer adds the **agent-product capabilities** that make
that core persistent and usable like a modern terminal agent.

## What was added

| Capability | X19 implementation |
|---|---|
| First-class procedural memory | `runtime.hermes_runtime.SkillStore` + `SKILL.md` |
| Learned skills | `promote_outcome()` turns successful mission knowledge into reviewable skills |
| Cross-session recall | SQLite FTS5 index over `SESSIONS_DIR` |
| Isolated subagents | `SubagentPool` with fresh context + private workspace |
| Parallel delegation | bounded thread pool; default 3 workers |
| Durable scheduled jobs | `CronStore` persisted to `~/.x19/cron_jobs.json` |
| Safe cron execution | only allow-listed X19 commands; no arbitrary shell execution |
| Runtime inspection | `x19 runtime` |
| Skills CLI | `x19 skills`, `x19 skill show/create/delete` |
| Session recall CLI | `x19 recall <query>` |
| Delegation CLI | `x19 delegate <goal> ...` |
| Cron CLI | `x19 cron list/add/pause/resume/remove/run/daemon` |

## Design principles borrowed from Hermes

### 1. Subagents get fresh context

A delegated worker does not inherit the parent conversation automatically.
The parent passes an explicit goal and context. This keeps the parent context
small and prevents accidental context contamination.

Workers get a private directory under `SUBAGENT_DIR` and return only a concise
handoff summary. The security-specific X19 swarm remains responsible for real
target execution, scope checks and finding verification.

### 2. Skills are procedural memory, not arbitrary self-modifying code

A learned skill is stored as a normal Markdown file. X19 can update a skill's
content and usage statistics, but learning does **not** silently rewrite Python
source code. This makes improvement reviewable, portable and reversible.

### 3. Session recall is local and searchable

Assessment session JSON files are indexed into SQLite FTS5. Recall returns the
actual stored session metadata rather than inventing a summary from memory.
The existing Chroma memory remains the semantic/security-memory layer; FTS5 is
the fast exact/keyword recall layer.

### 4. Cron is durable but constrained

Jobs survive process restarts because definitions are persisted. The daemon
executes only X19 subcommands from a small allow-list (`doctor`, `tools`,
`report`, `run`). Shell flags are rejected. Normal engagement scope and policy
gates still apply to an assessment launched by cron.

## Configuration

New settings can be controlled through `x19 config set` or environment
variables:

- `X19_SKILLS_DIR`
- `X19_SUBAGENT_DIR`
- `X19_SUBAGENT_MAX_CONCURRENT` (default 3)
- `X19_SUBAGENT_MAX_ITERATIONS` (default 12)
- `X19_SESSION_INDEX_DB`
- `X19_CRON_JOBS_FILE`
- `X19_CRON_POLL_SECONDS`
- `X19_AUTO_LEARN_SKILLS` (default enabled)

## Relationship to the security swarm

The runtime layer is intentionally **not** a replacement for the X19
security architecture. The existing specialist agents still handle:

`Recon → Web → Vulnerability Audit → Verification → Critic`

and the cognitive core still controls attack graphs, hypotheses, confidence,
policy and scope. Hermes-style features provide the persistent operating
system around that core: memory, reusable procedures, isolated delegation,
recall and automation.

## Terminal direction

The X19 terminal remains the primary interface. The next UI evolution should
keep the current live mission-control dashboard while adding:

- multiline command editing/history
- slash-command completion for runtime capabilities
- a delegation tree showing child state and final summaries
- skill/recall panes
- background job status
- interrupt-and-redirect semantics
- machine-readable `--json` output for every runtime surface

This keeps X19 terminal-native while bringing it closer to the usability model
of Hermes without copying Hermes' general-purpose identity.
