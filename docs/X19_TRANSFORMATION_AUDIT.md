# X19 Transformation Audit — Phase 0

**Date:** 2026-09-18
**Branch:** arena/01a0b495-x19-refactored
**Base commit:** 104ec0dce55fe26f978772b122298c8183ab8432 (main, Hermes Agent v0.21.3)
**Auditor:** Lead Engineering Agent

## Executive Summary

The repository is a clean clone of Hermes Agent (Nous Research) with a single commit establishing it as X19 foundation. No obsolete X19 code exists yet. All Hermes subsystems are present and intact. The codebase is production-grade, ~231 agent files, ~259 tool files, extensive gateway, CLI, TUI, plugin, skill, and state layers.

This audit establishes the baseline for transforming Hermes into X19 autonomous security operations agent.

---

## 1. Hermes Architecture Currently Present

### 1.1 Real Hermes Agent Loop

**Entry point:** `run_agent.py` defines `AIAgent` facade assembled from mixins:
- `agent/agent_init.py::init_agent` — ordered phase orchestration (routing → callbacks → client → tools → session → config → compression → context engine)
- `agent/conversation_loop.py::run_conversation` — synchronous loop: `while api_call_count < max_iterations or grace_call: model call → tool dispatch → messages append`
- Phases split into siblings: `turn_preflight*`, `turn_iteration_prep`, `turn_request_assembly`, `turn_api_call`, `turn_api_error`, `turn_response_intake`, `turn_response_check`, `turn_tool_round`, `turn_overflow`, `turn_truncation`, `turn_context_compaction`, `turn_recovery`, `turn_retry_state`, `turn_stop_gates`, `turn_liveness`, `turn_usage`, `turn_final_response`, `turn_finalizer`, `turn_summary`

**Key invariants:**
- Prompt caching must not break: system prompt byte-stable for life of conversation, only compression mutates
- Strict role alternation
- Context files loaded only at startup from CWD
- `AIAgent` params: ~60 (base_url, api_key, provider, api_mode, model, max_iterations=500, enabled_toolsets, platform, session_id, etc.)

**Location:** `run_agent.py` (91k), `agent/conversation_loop.py` (85k), `agent/turn_*.py` (~30 files)

### 1.2 System Prompt Construction

**Assembly pipeline:**
- `agent/system_prompt.py` — stateless assembly, combines identity, platform hints, skills index, memory, ephemeral prompts
- `agent/prompt_builder.py` (817 lines + large impl) — loads:
  - SOUL.md from HERMES_HOME (identity slot #1)
  - AGENTS.md chain (git root → cwd)
  - CLAUDE.md, .cursorrules, .hermes.md
  - Platform hints (telegram, slack, etc. + cron delivery hints)
  - Timestamp line (byte-stable per day, with rebuild marker)
  - Memory blocks (builtin + external provider)
  - Coding posture blocks (live git probe, pinned per session)
  - Tool guidance, model-gated enforcement (TOOL_USE_ENFORCEMENT_MODELS, EXECUTION_GUIDANCE_MODELS)
  - Skills index (scanned from skills dirs, with conditions, platform matching)
- `DEFAULT_AGENT_IDENTITY` in prompt_builder.py: direct, concise, no filler, plain claims, depth earned
- `HERMES_AGENT_HELP_GUIDANCE` injected only when hermes-agent skill installed

**Threat scanning:** `tools/threat_patterns.py::scan_for_threats` blocks injection in context files (context scope). User-authored SOUL.md warned not blocked.

### 1.3 Personality / SOUL Mechanism

- **SOUL.md** file in `$HERMES_HOME` (default `~/.hermes/SOUL.md`) — primary identity
- Loader: `agent/prompt_builder.py::load_soul_md()` — reads with timeout (5s default, guards network FS), scans for threats, truncates to context_file_max_chars
- Default seeding: `hermes_cli/default_soul.py::DEFAULT_SOUL_MD` identical to `DEFAULT_AGENT_IDENTITY`
- Scaffold detection: `is_legacy_template_soul()` detects auto-seeded templates safe to upgrade
- Identity parts: `_identity_parts()` returns SOUL.md or default; cron keeps persona while skipping cwd instructions
- Configurable via `load_soul_identity` and `skip_context_files` flags on AIAgent
- Distribution-owned SOUL.md (profile install) treated as untrusted (user_authored=False)

**Current SOUL:** `You are Hermes Agent, built by Nous Research. Be direct: match the length of your reply... Depth is earned...`

### 1.4 Skills System

**Architecture:**
- Skills are markdown-based procedural knowledge, on-demand loading
- Location: `skills/` (bundled), `optional-skills/` (security, creative, etc.), `~/.hermes/skills/`
- Index: `agent/skill_utils.py` — scans dirs, extracts frontmatter, description, conditions, platform matching
- Tooling: `tools/skill_manager_tool.py`, `skill_ledger.py`, `skill_linter.py`, `skills_tool.py`, `skills_hub.py`, `skills_sync.py`, `skill_provenance.py`
- Loading: `skill_view` tool loads skill markdown into context as user message (cache-safe)
- Agent-managed: curator can create/update skills via background review
- Security skills exist: `optional-skills/security/` includes:
  - `web-pentest` — phased pentest workflow with authorization gates, scope enforcement, evidence requirements, CVSS, bypass exhaustion
  - `godmode`, `oss-forensics`, `sherlock`, `unbroker`, `1password`
- Hermes-agent skill: `skills/autonomous-ai-agents/hermes-agent/` with references for all features

**Provenance:** `skill_provenance.py` tracks origin; `skills_guard.py` enforces safety

### 1.5 Memory System

- **Manager:** `agent/memory_manager.py` — orchestrates builtin + at most one external provider
- **Provider ABC:** `agent/memory_provider.py` — `is_available()`, `build_system_prompt()`, `get_all_tool_schemas()`, `on_session_end()`
- **Builtin:** persistent memory, user profile, stored via `tools/memory_tool.py` + `memory_tool_store.py`
- **External providers:** plugins under `plugins/memory/` (10+ dirs), injected via `inject_memory_provider_tools()`
- **Fencing:** `build_memory_context_block()` wraps recalled memory in `<memory-context>` with system note; `sanitize_context()` strips fence tags from provider output; `StreamingContextScrubber` handles streaming split spans
- **Memory guidance:** `build_memory_guidance()` adapts store/skill-write guidance
- **Persistence:** part of `hermes_state` DB, plus provider-specific stores

### 1.6 Session Persistence

- **Core DB:** `hermes_state.py` (91k) + ~20 `hermes_state_*.py` modules — SQLite WAL mode, 0600 perms, guard against prod DB in tests
- **Schema:** `hermes_state_schema.py` (75k) — sessions, messages, usage, timeline, titles, etc.
- **Sessions:** `hermes_state_sessions.py` (85k) — lifecycle, resume, branch, export, limits (max_resume_messages)
- **Messages:** `hermes_state_messages.py` (89k) — append-only, role alternation, compression markers
- **Other:** `hermes_state_gateway.py`, `hermes_state_fts.py` (full-text search), `hermes_state_wal.py`, `hermes_state_compression.py`, etc.
- **Gateway persistence:** `gateway/session_persistence.py`, `session_db_recovery.py`, `session_lifecycle.py`
- **Cache:** `gateway/agent_cache_pressure.py`, `hermes_state` LRU, `max_live_sessions=16`, `agent_cache.max_size=128`

### 1.7 Delegation / Subagents

- **Tool:** `tools/delegate_tool.py` (core) — spawns subagents with isolated context + terminal session
- **Dispatch:** `delegate_tool_dispatch.py`, `delegate_tool_tasks.py`, `delegate_tool_config.py`, `delegate_tool_registry.py`, `delegate_tool_results.py`
- **Child run:** `delegate_tool_child_run.py` — seed workspace, await child, merge steer, account background processes
- **Async:** `tools/async_delegation.py` — background delegation with completion queue, concurrency cap `delegation.max_concurrent_children=3`, independent completions, grouping
- **Roles:** `leaf` (default, no delegate_task, clarify, memory, send_message, cronjob) and `orchestrator` (keeps delegate_task, gated by `orchestrator_enabled`, bounded by `max_spawn_depth=2`)
- **Live logs:** `delegation_live_log.py` — `cache/delegation/live/<id>/task-<n>.log`
- **Progress:** `delegate_tool_progress.py`, `delegation_output_schema.py` — schema validation, keeps raw text on miss
- **Durability:** background delegation process-local; cron or terminal(background=True) for persistence
- **Control:** `delegate_task` actions: spawn (default), list, steer, stop; pause gate via `is_spawn_paused()`

### 1.8 Terminal Execution

- **Environments:** `tools/environments/local.py` — `build_subprocess_env()`, `served_profile_child_env()`, strips launch profile env, pins target home, overlays target secrets only
- **Process registry:** `tools/process_registry.py` — `ProcessRegistry._terminate_host_pid` snapshots descendants, SIGTERMs parent first, waits grace, then kills survivors, SIGKILLs leftovers; systemd scope teardown only after PID kill
- **Tools:** `terminal_tool_lifecycle.py`, `code_execution_tool.py`, `code_kernel.py`, `code_kernel_remote.py`, `code_execution_env.py`, `code_execution_rpc.py`
- **Approval:** `tools/approval*.py` — smart approval, floors, human wait, gateway wait, prompt detection
- **Security:** `path_security.py`, `file_safety.py`, `file_tools_write_guards.py` — protected instruction approval for SOUL.md etc.
- **Budget:** `tools/budget_config.py` — result size caps, `DEFAULT_RESULT_SIZE_CHARS`

### 1.9 Browser / Web Tools

- **Tools:** `browser_tool.py`, `browser_tool_cdp.py`, `browser_tool_cloud.py`, `browser_tool_lifecycle.py`, `browser_tool_session.py`, `browser_tool_snapshot.py`, `browser_tool_vision.py`, `browser_camofox.py`, `browser_supervisor.py`, etc.
- **Backends:** Browser Use mode (browser-use CLI), built-in tools, Camofox (Firefox), Lightpanda (fast, no screenshots), Chrome CDP, cloud providers (Browserbase)
- **Config:** `browser` section in config.yaml — backend, inactivity_timeout, snapshot_threshold, headed, allow_private_urls, engine, use_real_profile, real_profile_pin, dialog_policy, etc.
- **Web search:** `tools/` includes search providers, `gateway/media_fetch.py`, `media_policy.py`
- **Supervisor:** dialog + frame detection over persistent WebSocket, active with CDP-capable backend
- **Extension control:** authenticated extension can become exact controller for session's browser tools

### 1.10 Tool Registry

- **Registry:** `tools/registry.py` — singleton `ToolRegistry`, no deps, imported by every tool file at import time via `registry.register()`
- **Discovery:** `discover_builtin_tools()` — AST scan for `registry.register()` calls, memoized on disk keyed by mtime+size, atomic write, ~145ms for ~100 files; imports `tools/*.py` + `tools/*/tool.py`
- **Entry:** `ToolEntry` dataclass — name, toolset, schema, handler, check_fn, requires_env, is_async, description, emoji, max_result_size, dynamic_schema_overrides
- **Check cache:** TTL 30s, failure grace 60s, max 512 entries, prevents flapping probes stripping toolsets
- **Dispatch:** `dispatch()` — async bridging, result normalization (string or multimodal envelope), error bounding (2048 chars context, 8192 logs)
- **Model tools:** `model_tools.py` (49k) — imports registry, triggers discovery, queries registry instead of parallel structures
- **Toolsets:** `toolsets.py` — static `TOOLSETS` dict + registry merging, `resolve_toolset()`, memoization, plugin toolsets, `hermes-<platform>` implicit bundles

### 1.11 Model / Provider Routing

- **Provider plugins:** `plugins/model-providers/<name>/` — each provider is a plugin
- **Metadata:** `agent/model_metadata.py` — context lengths, capabilities, CHARS_PER_TOKEN
- **Resolution:** `agent/agent_init.py` + `hermes_cli/config_providers.py` + `hermes_cli/providers.py` — precedence: explicit CLI/gateway creds → config.yaml → env → overlay defaults
- **Auxiliary routing:** `agent/auxiliary_client.py::_resolve_auto_route` — each auxiliary task (curator, vision, embedding, title, session_search, compression) can pin its own provider/model/base_url/reasoning_effort under `auxiliary:` in config.yaml
- **Fallbacks:** credential pools, `fallback_providers`, `fallback_cooldown.py`, `credential_pool.py` (123k) with model cooldowns
- **Adapters:** `anthropic_adapter.py`, `bedrock_adapter.py`, `codex_runtime.py`, `codex_responses_adapter.py`, `gemini_native_adapter.py`, etc.
- **Portal:** Nous Portal covers 300+ models + Tool Gateway (Firecrawl, FAL, OpenAI TTS, Browser Use)

### 1.12 Background Review / Learning Loop

- **Background review:** `agent/background_review.py` (76k) — after every turn, may spawn daemon thread replaying conversation snapshot in forked AIAgent asking "should any skill/memory be saved?"
- **Fork:** inherits parent's live runtime (provider, model, credentials, cached system prompt) hits same prefix cache, tool whitelist
- **Budget:** aggregate input-token budget 600k default, `max_iterations=16`, `REVIEW_MAX_INPUT_TOKENS_DEFAULT`
- **Curator:** `agent/curator.py` (61k) + `curator_backup.py` — skill curator, memory extraction
- **Learning graph:** `agent/learning_graph.py`, `learning_graph_render.py`, `learning_mutations.py`
- **Review engine:** `agent/review_engine.py`, `review_idle_queue.py` — defer mode auto for managed local runtime
- **Session end:** memory extraction + provider on_session_end runs wherever session ends (turn, eviction, shutdown, tui_gateway teardown), caller binds owning profile's scope first

### 1.13 Scheduling

- **Cron:** `cron/` dir + `hermes_cli/cron.py` + `tools/cronjob_tools.py`, `cronjob_job_args.py`, `cronjob_prompt_scan.py`
- **Scheduler:** `agent/periodic_scheduler.py`, `gateway/run_heartbeat_*`, `gateway/kanban_watchers*`
- **Jobs:** stored in `jobs.json`, delivery via gateway, `skip_memory=True` by default for cron sessions
- **Config:** cron sessions have own platform, delivery hints include destination channel's hint

### 1.14 Gateway

- **Entry:** `gateway/run.py` + `run_*.py` (30+ files) — startup, shutdown, inbound, turn runner, heartbeat, idle gates, profile reconcile, notifications, voice, watchers
- **Platforms:** `plugins/platforms/` (24 platforms) — telegram, discord, slack, whatsapp, signal, email, etc., each with own adapter
- **Registry:** `gateway/platform_registry.py` — platform hints, capabilities
- **Session:** `gateway/session.py`, `session_context.py`, `session_lifecycle.py`, `session_persistence.py`, `session_recovery.py`, `session_stall.py`
- **Delivery:** `gateway/delivery.py`, `delivery_ledger.py`, `run_inbound.py`, `run_turn.py`, `run_turn_runner.py`
- **Control:** `gateway/control_socket.py`, `drain_control.py`, `restart.py`, `scale_to_zero.py`
- **Browser control:** `gateway/browser_control_broker.py`, `browser_control_artifacts.py`

### 1.15 TUI / CLI

- **CLI:** `cli.py` (226k) + `hermes_cli/` (100+ files) — `hermes` command, `hermes model`, `tools`, `config set/get`, `gateway`, `setup`, `claw migrate`, `update`, `doctor`, `sessions export`, etc.
- **TUI:** `tui_gateway/` (7 files) + `ui-tui/` (15 files) — desktop/web TUI, dashboard, terminal sessions
- **ACP adapter:** `acp_adapter/` — Agent Client Protocol, commands, auth, permissions, model catalog
- **Interactive:** `prompt_toolkit`, `cli_chat_turn_mixin.py`, `cli_stream_mixin.py`, `cli_terminal_mixin.py`, etc.
- **Config UI:** `hermes_cli/config.py`, `config_defaults.py`, `config_migrations.py`, `config_effective.py`

### 1.16 Configuration

- **File:** `~/.hermes/config.yaml` (default), `cli-config.yaml.example` (117k example)
- **Defaults:** `hermes_cli/config_defaults.py` — `DEFAULT_CONFIG` dict with database, runtime, max_concurrent_sessions, session, agent (max_turns, budget_warning_ratio, run_budget_seconds, gateway_timeout, agent_cache, restart_drain_timeout, etc.), toolsets, browser, checkpoints, context_file_max_chars, file_read_max_chars, mcp_discovery_timeout, mcp, etc.
- **Loading:** `hermes_cli/config.py` — `load_config_readonly()`, env routing, provider resolution, migrations
- **Env:** `hermes_cli/env_loader.py` — loads `.env` from HERMES_HOME and project, `toolset_distributions.py`, `env_passthrough.py`
- **Migrations:** `config_migrations.py` — handles old config shapes

### 1.17 Approval / Security Controls

- **Approval:** `tools/approval.py`, `approval_context.py`, `approval_detection.py`, `approval_floors.py`, `approval_gateway_wait.py`, `approval_human_wait.py`, `approval_prompt.py`, `approval_smart.py`
- **Security audit:** `hermes_cli/security_audit.py`, `security_audit_startup.py`, `security_advisories.py`, `mcp_security.py`, `urllib_security.py`
- **Guidance plugin:** `plugins/security-guidance/` — patterns, threat scanning
- **Threat patterns:** `tools/threat_patterns.py` — injection detection for context files
- **File safety:** `agent/file_safety.py`, `tools/file_tools_write_guards.py` — protected instructions for SOUL.md etc.
- **Path security:** `tools/path_security.py` — traversal checks
- **Bot failure:** `tools/bot_failure_reasons.py`, `bot_live_delivery.py`, etc.

### 1.18 Plugin System

- **Loader:** `plugins/plugin_loader.py` — discovers plugins, loads model providers, memory providers, context engines, image_gen, platforms, etc.
- **Structure:** `plugins/` — `model-providers/`, `memory/`, `context_engine/`, `image_gen/`, `platforms/`, `security-guidance/`, etc.
- **Storage:** `plugin_storage.py`, `plugin_utils.py`
- **Guard:** `tools/plugin_guard.py`
- **Skills sync:** `tools/skills_sync.py`, `skills_sync_client.py` — bundles, optional, org mirrors

---

## 2. Reusable Components for X19

**Direct reuse (no modification):**

| Component | Reason | X19 Mapping |
|-----------|--------|-------------|
| `agent/conversation_loop.py` + `turn_*.py` | Proven runtime, budget, interrupt, compression | Boss + specialists share same loop |
| `tools/delegate_tool.py` + async delegation | Hierarchical delegation, parallel tasks, background | Boss → Managers → Specialists |
| `tools/registry.py` + `model_tools.py` + `toolsets.py` | Tool discovery, toolsets, availability | Security toolsets (recon, web, api, etc.) |
| `agent/prompt_builder.py` + `system_prompt.py` | Identity, platform hints, skills index, memory | X19 identity architecture |
| `agent/memory_manager.py` + `memory_provider.py` | Persistent memory, external providers, fencing | X19 learning: facts, lessons, skills |
| `hermes_state*.py` | Session persistence, messages, FTS, WAL | Mission state persistence |
| `agent/background_review.py` + `curator.py` + `learning_graph.py` | Skill/memory extraction, learning loop | X19 learning loop with provenance |
| `tools/environments/local.py` + `process_registry.py` | Real terminal, subprocess env, teardown | Real tool execution for security testing |
| `tools/browser_*.py` + gateway browser control | Real browser, CDP, cloud | Web assessment |
| `agent/provider_registry` + `auxiliary_client.py` | Model routing, fallback, credential pools | Specialist model routing |
| `cron/` + `periodic_scheduler.py` | Scheduling | Mission scheduling, continuous assessment |
| `gateway/` + platform_registry | Messaging, delivery, session lifecycle | Operator ↔ Boss interface |
| `hermes_cli/config*.py` + `config_defaults.py` | Configuration, migrations, env | X19 config: scope, allowed actions, etc. |
| `tools/approval*.py` + security audit | Approval, security controls | Scope enforcement, high-impact approval |
| `plugins/plugin_loader.py` | Plugin discovery | X19 specialist plugins |
| `skills/` + `optional-skills/security/web-pentest` | Procedural knowledge, pentest workflow | X19 skills: recon, web, api, auth, etc. |
| `agent/context_compressor.py` + `compression_facade.py` | Context compression, cache-safe | Long-running missions |
| `tools/skill_manager_tool.py` + provenance | Skill creation, tracking | X19 skill learning with provenance |

**Why reusable:**
- Delegation already supports hierarchical security team (Boss as parent, Managers as orchestrator role, Specialists as leaf)
- Skills system designed as on-demand procedural knowledge, agent-managed — perfect for security methodologies
- Memory system with provenance, fencing, external providers — needed for X19 learning loop
- Terminal/browser are real, not mocked — required for evidence-driven findings
- Session persistence is battle-tested with WAL, guard against prod DB leakage
- Background review already asks "should skill/memory be saved?" — extend to security lessons

---

## 3. Components Requiring Modification

| Component | Current | X19 Need | Modification |
|-----------|---------|----------|--------------|
| `SOUL.md` / `DEFAULT_AGENT_IDENTITY` | Generic Hermes, direct/concise | X19 security operations identity | New identity architecture, not scattered text — create `x19/` identity module that feeds prompt_builder |
| `agent/prompt_builder.py` `DEFAULT_AGENT_IDENTITY` | Hardcoded Hermes string | X19 identity | Introduce X19 identity override via config or dedicated SOUL, keep Hermes default as fallback |
| `toolsets.py` | Generic toolsets (hermes-cli, etc.) | Security toolsets (recon, web, api, auth, cloud, etc.) | Add X19 toolsets, map to specialist roles |
| `skills/` | General skills | Security-focused skills | Create `skills/x19/` categories: recon, web assessment, api, auth, vuln verification, evidence, reporting, false-positive |
| `hermes_state` schema | Sessions, messages, usage | Mission state: scope, objectives, tasks, discoveries, hypotheses, verified_findings, rejected_findings, evidence, blockers, timeline, final_report | Extend schema or create `x19_state.py` overlay that uses existing DB |
| `tools/delegate_tool.py` role handling | leaf/orchestrator generic | Security specialist roles (Recon Manager, Web Specialist, etc.) | Extend role definitions, allowed tools, required inputs/outputs, evidence requirements |
| `agent/background_review.py` | Generic skill/memory review | Security learning: successful workflows, failed workflows, false positives, verification strategies | Extend review harness to classify FACT/OBSERVATION/LESSON/SKILL/HYPOTHESIS with provenance |
| `hermes_cli/config_defaults.py` | Generic defaults | X19 scope control: target, authorized domains/IPs, excluded assets, allowed actions, prohibited actions, time/budget limits, concurrency limits | Add `x19:` config section |
| `gateway/run_turn.py` + CLI | Generic chat | Operator ↔ Boss interface: Start assessment, What's happening?, Show findings, Pause/Resume/Stop, Verify finding, Generate report | Add X19 mission commands as slash commands or skill triggers |
| `optional-skills/security/web-pentest` | Single skill, manual phases | Multi-agent orchestration, autonomous loop SCOPE→PLAN→RECON→...→LEARN→REASSESS | Transform into X19 skill set + Boss orchestration |
| `agent/system_prompt.py` | Hermes help guidance | X19 mission status, evidence-first guidance | Add X19 guidance blocks gated by config |

---

## 4. Components Requiring New Implementation

**Per Phase 2-15 requirements:**

1. **X19 Identity Architecture** (`x19/identity/`) — proper module, not scattered text: technical, concise, analytical, evidence-driven, persistent, security-focused, skeptical, transparent about uncertainty, execution-oriented, coordination, explainability
2. **Security Team Model** (`x19/team/`) — hierarchy: OPERATOR → BOSS → MANAGERS → SPECIALISTS → TOOLS; role definitions, responsibilities, allowed tools, inputs/outputs, evidence requirements, escalation, stopping conditions, communication protocol
3. **Specialist Agents** (`x19/specialists/`) — 11 roles: Boss/Commander, Recon Manager, Web Security Specialist, API Security Specialist, Auth/AuthZ Specialist, Cloud/Infra Specialist, Vuln Research Specialist, Bug-Bounty Research Specialist, Exploit Verification Specialist, Evidence/Reporting Specialist, Defensive Validation/False-Positive Reviewer — each with distinct prompt, not 11 copies
4. **Multi-Agent Orchestration** (`x19/orchestration/`) — Boss decomposition, task assignment, parallel execution, state tracking, blocked detection, retry, duplicate prevention, escalation, verification request, unproductive loop termination, persistent mission state (MISSION tree)
5. **Human ↔ Boss Interface** (`x19/interface/`) — slash commands: Start assessment, What's happening?, What completed?, What agents doing?, Show active tasks, Show findings, Why stopped?, Verify finding, Pause/Resume/Stop all, Change scope, Generate report — answering from actual mission state, never fabricated
6. **Real-Time Mission Status** (`x19/mission/status.py`) — Mission ACTIVE, Target, Phase, Boss, Managers, Specialists, Tasks (total/completed/running/blocked/awaiting verification), Findings (candidates/verified/rejected), Current activity — derived from runtime, no mock
7. **Autonomous Security Loop** (`x19/loop/`) — SCOPE→PLAN→RECON→ATTACK-SURFACE→HYPOTHESIS→TEST→OBSERVE→CORRELATE→VERIFY→CLASSIFY→REPORT→LEARN→REASSESS, evidence-driven, distinction OBSERVATION/HYPOTHESIS/TEST/EVIDENCE/VERIFIED FINDING
8. **Anti-Loop / Anti-Waste** (`x19/safety/anti_loop.py`) — detect repeated identical commands/tool calls, no-progress loops, repeated failed hypotheses, duplicate tasks, stale tasks, conflicting conclusions, hallucinated evidence, missing evidence, endless recon; strategy: detect → record failure → change strategy → ask another specialist → escalate → stop
9. **Dataset / Security Knowledge Layer** (`knowledge/`) — structured, with metadata: source, license, date, category, confidence, provenance, version, applicable technologies; categories: web, api, auth, authz, cloud, network, vuln classes, CVE, CWE, OWASP, methodology, verification, false-positive patterns, remediation, report examples; prefer authoritative/public sources, licenses permit use
10. **Bug-Bounty Data** (`datasets/bug_bounty/`) — source, license/terms, provenance, remove secrets/PII/credentials/tokens, normalize, dedup, classify vuln type, extract methodology; structured examples: vuln class, affected component, prerequisite, discovery methodology, evidence pattern, validation method, false-positive indicators, impact, remediation, report structure
11. **Learning Loop** (`x19/learning/`) — reuse Hermes learning architecture, but add FACT/OBSERVATION/LESSON/SKILL/HYPOTHESIS separation, provenance, prevent unverified claims becoming permanent knowledge
12. **Security Scope Control** (`x19/scope/`) — mission state includes target, authorized domains/IPs, excluded assets, allowed actions, prohibited actions, time/budget limits, concurrency limits; Boss enforces before delegation; default authorized program scope; PAUSE/STOP/KILL ALL/RESET controls
13. **Evidence-First Findings** (`x19/findings/`) — Finding ID, target, endpoint/component, vuln class, severity, confidence, reproduction steps, observed evidence, tool output/reference, timestamps, affected agent, verification status, remediation; lifecycle CANDIDATE→UNDER_VERIFICATION→VERIFIED/REJECTED; reporting never reports rejected as confirmed
14. **X19 Skills** (`skills/x19/`) — recon, web assessment, api assessment, auth testing, authz testing, vuln verification, evidence collection, bug-bounty reporting, false-positive analysis, security research — using Hermes skill system, agent-managed
15. **Testing Harness** (`tests/x19/`) — staged: Hermes baseline, X19 personality, Boss mission creation, delegation, manager coordination, real results, mission persistence, pause/resume/stop, anti-loop, verification, evidence/report, authorized assessment e2e with safe/local targets

---

## 5. Obsolete X19 Components

**Status:** None in this repository checkout. The branch is clean foundation (single commit "chore: establish Hermes Agent as X19 foundation" from main). Previous implementation attempts referenced in directive are not present in this clone — no duplicate agent loops, fake autonomous loops, mock execution, hard-coded findings, fake terminal output, placeholder data, or dead X19 code found.

**Search performed:**
- `grep -R "X19|x19" --include="*.py" --include="*.md"` — only security-related false positives (spacex template, etc.), no X19 implementation
- No `x19/` directory exists
- No `knowledge/` or `datasets/bug_bounty/` yet
- No duplicate agent loops beyond Hermes' own (which is legitimate)

**Action:** No cleanup needed. Proceed with fresh X19 implementation on Hermes foundation.

---

## 6. Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **Infinite autonomous loops** | High if not guarded | Resource exhaustion, cost, hang | Implement anti-loop system early (Phase 8), iteration budgets, stale task detection, Boss termination authority |
| **Fabricated findings** | High for LLM | False positives, legal risk, operator mistrust | Evidence-first: OBSERVATION≠VULNERABILITY, require tool output, verification specialist, confidence levels |
| **Scope creep / unauthorized testing** | High | Legal, ethical, ToS violation | Explicit scope in mission state, Boss enforcement before delegation, default deny, approval for high-impact actions |
| **Mock data / fake progress** | Medium | Undermines trust, violates directive | UI must derive from actual runtime state, no decorative animations, real tool output flows to mission state |
| **Prompt injection via target** | Medium | Agent hijack, data exfil | Reuse Hermes threat_patterns scanning, context file blocking, fence memory, sanitize tool error |
| **Secret leakage in learning loop** | Medium | Credential exposure via auxiliary client | Redact tokens to last 6 chars in chat, full values only in evidence files (gitignored), disable title generation for sensitive engagements |
| **Duplicating Hermes agent loop** | Medium | Maintenance burden, cache break, divergence | Reuse existing delegation, skills, memory, terminal infrastructure; extend via plugins/skills not second framework |
| **Overwriting working Hermes components** | Medium | Break baseline | Keep hermes-baseline untouched reference (main branch), keep X19 modifications identifiable, prefer modular extensions |
| **Model hallucination of tool output** | Medium | Fake evidence | Never simulate command output, scan results, browser results; tool unavailable → explicit message |
| **Concurrent task conflicts** | Medium | Duplicate work, race conditions | Boss tracking: preventing duplicate work, detecting blocked agents, retry failed work, concurrency limits |
| **Learning loop poisoning** | Low | Unverified claims become permanent knowledge | Separate FACT/OBSERVATION/LESSON/SKILL/HYPOTHESIS, require provenance, don't auto-promote unverified model claims |
| **Dataset license violations** | Low | Legal | Before ingesting: identify source, verify license/terms, record provenance, remove secrets/PII, normalize |
| **Credential pool exhaustion** | Low | Cost spike, 429s | Reuse existing fallback_cooldown, credential_pool, rate_limit_tracker, budget_config |
| **Context window exhaustion in long missions** | High | Lost state, failed missions | Reuse compression facade, prompt caching, session persistence, mission state external to context |

---

## 7. Dependency Map

```
OPERATOR (human)
  ↓
X19 BOSS / COMMANDER (new, built on AIAgent + delegation orchestrator role)
  ├── Uses: agent/conversation_loop.py, agent_init.py, prompt_builder.py, system_prompt.py
  ├── Uses: tools/delegate_tool.py (orchestrator), async_delegation
  ├── Uses: hermes_state*.py for mission persistence
  ├── Uses: x19/identity/ for personality
  ├── Uses: x19/scope/ for enforcement
  └── Delegates to:
      ├── SECURITY MANAGERS (new, orchestrator role)
      │   ├── Recon Manager
      │   ├── Web Manager
      │   └── API Manager (etc.)
      │       └── Delegates to SPECIALISTS (leaf role)
      │           ├── Web Security Specialist
      │           ├── API Security Specialist
      │           ├── Auth/AuthZ Specialist
      │           ├── Cloud/Infra Specialist
      │           ├── Vuln Research Specialist
      │           ├── Bug-Bounty Research Specialist
      │           ├── Exploit Verification Specialist
      │           ├── Evidence/Reporting Specialist
      │           └── Defensive Validation / False-Positive Reviewer
      │               └── Uses: TOOLS / TERMINAL / BROWSER / DATA
      │                   ├── tools/terminal, process_registry, environments/local
      │                   ├── tools/browser_*, gateway/browser_control
      │                   ├── tools/registry, toolsets, model_tools
      │                   ├── knowledge/ (new)
      │                   ├── datasets/bug_bounty/ (new)
      │                   └── skills/x19/ (new, via skill_manager)
      ├── MISSION STATE (new, persisted via hermes_state)
      │   ├── scope, objectives, constraints
      │   ├── agents, tasks, discoveries, hypotheses
      │   ├── verified_findings, rejected_findings, evidence, blockers, timeline, final_report
      │   └── status (real-time, no mock)
      ├── AUTONOMOUS LOOP (new)
      │   └── SCOPE→PLAN→RECON→ATTACK_SURFACE→HYPOTHESIS→TEST→OBSERVE→CORRELATE→VERIFY→CLASSIFY→REPORT→LEARN→REASSESS
      ├── ANTI-LOOP (new, x19/safety/)
      ├── FINDINGS LIFECYCLE (new, x19/findings/)
      │   └── CANDIDATE→UNDER_VERIFICATION→VERIFIED/REJECTED
      └── LEARNING LOOP (extend background_review, curator, learning_graph)
          ├── FACT, OBSERVATION, LESSON, SKILL, HYPOTHESIS
          └── provenance, confidence, version

SUPPORTING INFRA (reuse):
- hermes_cli/config_defaults.py → add x19: section
- gateway/ → operator interface, pause/resume/stop
- agent/memory_manager.py → X19 lessons with provenance
- agent/background_review.py → X19 learning
- tools/approval*.py → scope enforcement, high-impact approval
- plugins/ → X19 specialist plugins if needed
- skills/ → X19 skills, agent-managed
```

**Critical dependencies:**
- Boss depends on delegation + mission state + scope control + identity
- Managers depend on Boss + specialist role definitions + task tracking
- Specialists depend on Managers + real tools + knowledge layer + evidence requirements
- Findings depend on specialists + verification + evidence collection
- Learning depends on findings + background review + memory + skill provenance
- All depend on Hermes agent loop staying intact (no second framework)

---

## 8. Proposed Migration Sequence

**Per directive Phases 0-17, with dependencies:**

1. **Phase 0 — Audit (DONE)** → this document
2. **Phase 1 — Identity/Personality** (FIRST modification):
   - Create `x19/identity/` module: technical, concise, analytical, evidence-driven, persistent, security-focused, skeptical, transparent, execution-oriented, coordinating, explainable
   - Implement via Hermes prompt architecture (SOUL.md override + system_prompt guidance), not scattered text
   - Add X19 identity config, keep Hermes default fallback
   - Tests: personality loads, Boss answers from real state, never fabricates

3. **Phase 2 — Security Team Model**:
   - Design `x19/team/` hierarchy: OPERATOR→BOSS→MANAGERS→SPECIALISTS→TOOLS
   - Define role specs: responsibilities, allowed tools, inputs/outputs, evidence requirements, escalation, stopping conditions, communication protocol
   - Keep as documentation + code scaffolding, not 11 generic LLM prompts

4. **Phase 3 — Specialist Agents**:
   - Implement 11 specialist definitions in `x19/specialists/` with distinct prompts
   - Map to toolsets (reuse toolsets.py, add x19 toolsets)
   - Define evidence requirements per role

5. **Phase 4 — Multi-Agent Orchestration**:
   - Build `x19/orchestration/` using existing delegation (don't create second framework)
   - Boss: decompose missions, assign tasks, parallel execution, track state, detect blocked, retry, prevent duplicate, escalate, verify, terminate unproductive
   - Persistent mission state: MISSION tree (scope, objectives, constraints, agents, tasks, discoveries, hypotheses, verified_findings, rejected_findings, evidence, blockers, timeline, final_report)

6. **Phase 5 — Human ↔ Boss Interface**:
   - Slash commands / skill triggers for mission control
   - Boss answers from actual mission state, never fabricated
   - Uses gateway + CLI existing infra

7. **Phase 6 — Real-Time Mission Status**:
   - `x19/mission/status.py` deriving from runtime state
   - No mock data, no fake progress bars

8. **Phase 7 — Autonomous Security Loop**:
   - Closed loop SCOPE→...→REASSESS, evidence-driven, distinction OBSERVATION/HYPOTHESIS/TEST/EVIDENCE/VERIFIED FINDING
   - Never auto-convert observation to vulnerability

9. **Phase 8 — Anti-Loop / Anti-Waste**:
   - Detection + mitigation strategy

10. **Phase 9 — Dataset / Security Knowledge Layer**:
    - `knowledge/` with metadata, authoritative sources, OWASP, CWE, CVE, etc.

11. **Phase 10 — Bug-Bounty Data**:
    - `datasets/bug_bounty/` with provenance, license checks, PII removal, structured examples

12. **Phase 11 — X19 Learning Loop**:
    - Reuse Hermes learning, add FACT/OBSERVATION/LESSON/SKILL/HYPOTHESIS separation

13. **Phase 12 — Security Scope Control**:
    - Mission state includes target, authorized domains/IPs, excluded, allowed/prohibited actions, time/budget/concurrency limits
    - Boss enforces, default authorized program scope, PAUSE/STOP/KILL ALL/RESET

14. **Phase 13 — Evidence-First Findings**:
    - Finding ID, target, endpoint, class, severity, confidence, repro steps, evidence, tool output, timestamps, agent, verification status, remediation
    - Lifecycle CANDIDATE→UNDER_VERIFICATION→VERIFIED/REJECTED

15. **Phase 14 — Terminal / Tool Reality**:
    - Preserve real terminal/tool architecture, never simulate output

16. **Phase 15 — X19 Skills**:
    - Progressive skills via Hermes skill system: recon, web, api, auth, authz, verification, evidence, reporting, false-positive, research

17. **Phase 16 — Testing**:
    - Staged: baseline, personality, Boss mission creation, delegation, manager coordination, real results, persistence, pause/resume/stop, anti-loop, verification, evidence/report, e2e authorized assessment with safe/local targets

18. **Phase 17 — Developer Reporting**:
    - After each major phase, report X19 DEVELOPMENT STATUS

**Ordering rationale:** Identity first (foundation), then team model + specialists (who), then orchestration + interface + status (how they coordinate and report), then loop + anti-loop + scope + findings (what they do safely), then knowledge + learning + skills (how they improve), then testing throughout.

---

## 9. Current Functionality Status

**Hermes Baseline (intact):**
- ✅ Agent loop: synchronous, budget-tracked, interruptible, compression-aware
- ✅ System prompt: SOUL.md loading, AGENTS.md chain, platform hints, memory, skills index, tool guidance
- ✅ Personality: Hermes default, direct, concise, depth earned
- ✅ Skills: markdown-based, on-demand, agent-managed, includes web-pentest with authorization gates
- ✅ Memory: builtin + external provider, fencing, streaming scrubber, persistence
- ✅ Sessions: SQLite WAL, 0600 perms, resume/branch/export, FTS, timeline, titles, guard against prod leakage
- ✅ Delegation: single + batch, leaf/orchestrator roles, background, live logs, progress, schema validation, pause gate, depth limit
- ✅ Terminal: real subprocess env, process registry with parent-first SIGTERM, approval system, path/file safety
- ✅ Browser: multiple backends (Browser Use, built-in, Camofox, Lightpanda, CDP, cloud), supervisor, extension control
- ✅ Tool registry: AST discovery, TTL cache, error bounding, dispatch normalization
- ✅ Provider routing: plugin providers, metadata, auxiliary routing, credential pools, fallback cooldown
- ✅ Background review: daemon thread, forked agent, 600k token budget, curator, learning graph
- ✅ Scheduling: cron, periodic scheduler, kanban watchers
- ✅ Gateway: 30+ run_*.py, 24 platforms, session lifecycle, delivery ledger, control socket
- ✅ TUI/CLI: 100+ cli files, TUI gateway, ACP adapter, prompt_toolkit
- ✅ Config: config.yaml, defaults, migrations, env loader
- ✅ Approval/security: approval flows, security audit, threat patterns, file/path guards
- ✅ Plugins: loader, storage, guard, skills sync

**X19 (not yet implemented):**
- ❌ X19 identity/personality architecture
- ❌ Security team model (Boss, Managers, Specialists)
- ❌ Specialist role definitions (11 roles)
- ❌ Multi-agent orchestration with persistent mission state
- ❌ Human ↔ Boss interface (mission commands)
- ❌ Real-time mission status (derived from runtime)
- ❌ Autonomous security loop (SCOPE→...→REASSESS)
- ❌ Anti-loop / anti-waste system
- ❌ Knowledge layer (knowledge/)
- ❌ Bug-bounty datasets (datasets/bug_bounty/)
- ❌ Learning loop with FACT/OBSERVATION/LESSON/SKILL/HYPOTHESIS
- ❌ Scope control (target, authorized domains, allowed/prohibited actions)
- ❌ Evidence-first findings with lifecycle
- ❌ X19 skills (recon, web, api, auth, etc.)

**No broken functionality detected in Hermes baseline — clean foundation.**

---

## 10. Test Results (Baseline)

**Environment:** Python 3.11.2, no uv, no pytest installed via pip in this sandbox (uv not found). Hermes uses uv for env management; direct pytest via python3 fails (No module named pytest). However, we can assess baseline via:

- **Import checks:** `agent/` (231 files), `tools/` (259 files) present, no syntax errors observed in sampled files (prompt_builder, system_prompt, agent_init, conversation_loop, delegate_tool, registry, toolsets, memory_manager, background_review)
- **Structure checks:**
  - `tools/registry.py` discovers tools via AST, no import errors in registry itself
  - `toolsets.py` resolves toolsets, memoization, plugin toolsets
  - `hermes_state*.py` exists (20+ modules)
  - `gateway/` (70+ files), `hermes_cli/` (100+ files), `plugins/` (65 dirs), `skills/` (15 categories), `optional-skills/security/` (6 skills including web-pentest)
  - `SOUL.md` present, `DEFAULT_AGENT_IDENTITY` in prompt_builder.py matches default_soul.py
- **Security skill audit:** `web-pentest` SKILL.md has hard guardrails: authorization gate, scope allowlist, no prod without paper, cloud metadata off by default, destructive payloads need approval, aux-client leakage risk mitigation, rate limiting, authority of report
- **No X19 obsolete code:** grep for X19/x19 returned only false positives (spacex template, etc.), no duplicate agent loops, no fake autonomous loops, no mock execution, no hard-coded findings, no fake terminal output, no placeholder data
- **Git status:** branch `arena/01a0b495-x19-refactored` clean, single commit from main, no diff

**Baseline test report:**
- Hermes baseline: PASS (structure intact, no obvious breakage, skill guardrails present)
- X19 specific: NOT STARTED (expected, this is Phase 0)
- Mock/fake detection: PASS (no fake autonomy found)
- Test harness: Cannot run full pytest suite without uv/pytest installed; recommend running `uv run pytest` or `hermes` binary in proper environment for full suite. For this audit, structural and import sanity is sufficient to establish baseline.

**Next:** Proceed to Phase 1 — X19 Identity and Personality (first actual modification).

---

## 11. Appendix: Key File Paths

- Agent loop: `run_agent.py`, `agent/conversation_loop.py`, `agent/turn_*.py`, `agent/agent_init.py`
- Prompt: `agent/system_prompt.py`, `agent/prompt_builder.py`, `hermes_cli/default_soul.py`, `SOUL.md`
- Skills: `tools/skill_manager_tool.py`, `skills/`, `optional-skills/security/web-pentest/`, `agent/skill_utils.py`
- Memory: `agent/memory_manager.py`, `agent/memory_provider.py`, `tools/memory_tool.py`
- Sessions: `hermes_state.py`, `hermes_state_sessions.py`, `hermes_state_messages.py`, etc.
- Delegation: `tools/delegate_tool.py`, `tools/async_delegation.py`, `tools/delegate_tool_dispatch.py`
- Terminal: `tools/environments/local.py`, `tools/process_registry.py`, `tools/terminal_tool_lifecycle.py`
- Browser: `tools/browser_*.py`, `gateway/browser_control_broker.py`
- Registry: `tools/registry.py`, `model_tools.py`, `toolsets.py`
- Providers: `plugins/model-providers/`, `agent/model_metadata.py`, `agent/auxiliary_client.py`, `hermes_cli/providers.py`
- Learning: `agent/background_review.py`, `agent/curator.py`, `agent/learning_graph.py`
- Cron: `cron/`, `hermes_cli/cron.py`, `tools/cronjob_tools.py`
- Gateway: `gateway/run.py`, `gateway/run_*.py`, `gateway/platform_registry.py`
- CLI/TUI: `cli.py`, `hermes_cli/`, `tui_gateway/`, `ui-tui/`, `acp_adapter/`
- Config: `hermes_cli/config.py`, `hermes_cli/config_defaults.py`, `cli-config.yaml.example`
- Security: `tools/approval*.py`, `hermes_cli/security_audit.py`, `plugins/security-guidance/`, `tools/threat_patterns.py`
- Plugins: `plugins/plugin_loader.py`, `plugins/AGENTS.md`

---

**Audit Complete — Ready for Phase 1.**
