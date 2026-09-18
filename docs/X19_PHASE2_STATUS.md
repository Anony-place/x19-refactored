# X19 Phase 2 — Security Team Hierarchy — COMPLETE

**Date:** 2026-09-18
**Branch:** arena/01a0b495-x19-refactored
**Phase:** 2 — Security Team Hierarchy (Boss→Managers→Specialists)

## Summary

Implemented hierarchical security team model using Hermes' existing delegation infrastructure, not a second framework. All components reuse Hermes runtime, tool, delegation, terminal, and session architecture.

## Implemented Components

### 1. Team Roles (`x19/team/roles.py`)

- **13 roles total**, 11 core as defined in audit:
  - Boss/Commander (boss) — orchestrator, owns mission, defines scope, delegates, tracks state
  - Recon Manager (recon_manager) — orchestrator, asset discovery, endpoint enum, tech fingerprint
  - Web Manager (web_manager) — orchestrator, web app assessment coordination
  - API Manager (api_manager) — orchestrator, API surface coordination
  - Web Security Specialist (web_security) — leaf, XSS, SQLi, SSTI, SSRF, XXE, etc.
  - API Security Specialist (api_security) — leaf, BOLA, BFLA, injection, mass assignment
  - Auth/AuthZ Specialist (auth) — leaf, auth bypass, IDOR, privilege escalation
  - Cloud/Infra Specialist (cloud_infra) — leaf, S3, IAM, metadata, open ports
  - Vuln Research Specialist (vuln_research) — leaf, correlate observations against CWE/OWASP/CVE
  - Bug-Bounty Research Specialist (bugbounty_research) — leaf, program scope, impact assessment
  - Exploit Verification Specialist (verification) — leaf, reproduce findings, bypass exhaustion
  - Evidence/Reporting Specialist (evidence_reporting) — leaf, evidence collection, reporting L3/L4 only
  - Defensive Validation/False-Positive Reviewer (defensive_validation) — leaf, false positive review

- Each role has:
  - Distinct prompt fragment (not 11 copies) — verified unique
  - Responsibilities, allowed tools, required inputs/outputs, evidence requirements
  - Escalation path, stopping conditions, prohibited actions
  - Toolset mapping (x19-recon, x19-web, etc.)
  - Delegation role: orchestrator (Boss/Managers) or leaf (Specialists)

### 2. Team Hierarchy (`x19/team/hierarchy.py`)

- **Hierarchy:** OPERATOR → BOSS → MANAGERS → SPECIALISTS → TOOLS
- **Delegation rules:** Who can delegate to whom, with scope enforcement
  - Boss can delegate to any Manager or Specialist (flexible for small/large missions)
  - Managers coordinate Specialists (Recon → Web/API, Web → Web/Auth/Verification, API → API/Auth/Cloud)
  - Specialists are leaf — cannot delegate (enforced by Hermes delegation_role)
- **Communication protocol:**
  - Downward: goal + context + scope + expected_evidence
  - Upward: evidence + status + next_steps (must have tool output, never fabricated)
  - Horizontal: via Boss or shared mission state, not direct
- **Validation:** Hierarchy validated, no cycles, all roles exist, leaf cannot delegate

### 3. Specialists (`x19/specialists/`)

- **Base (`base.py`):** Build specialist goals, contexts, configs for delegation
  - Uses RoleDefinition from team/roles.py
  - Generates distinct prompts per role
  - Maps to Hermes delegate_task args: goal, context, toolsets, role, max_iterations
- **Wrappers:** boss.py, recon_manager.py, web_manager.py, api_manager.py, web_security.py, api_security.py, auth.py, cloud_infra.py, vuln_research.py, bugbounty_research.py, verification.py, evidence_reporting.py, defensive_validation.py
  - Each wrapper exposes get_prompt(), build_goal(), build_context() with role-specific logic
  - Distinct prompts, not copies

### 4. Scope Control (`x19/scope/scope.py`)

- **ScopeDefinition:** target, authorized domains/IPs/ranges, excluded assets/IPs, allowed/prohibited actions, time/budget/concurrency limits, rate limiting
- **Defaults:**
  - Allowed (low-risk recon): read_only_get, header_analysis, endpoint_discovery, tech_fingerprint, subdomain_enum
  - Prohibited (high-risk, require approval): destructive_payload, data_deletion, dos, brute_force, cloud_metadata_probing, etc.
  - High-impact requiring approval: destructive_payload, auth_bypass_attempt, cloud_metadata_probing, production_testing, brute_force, etc.
- **ScopeEnforcer:**
  - Domain authorization with wildcard support (*.target.com)
  - IP authorization with CIDR ranges
  - Excluded asset detection
  - Action allowed/prohibited enforcement
  - Approval required for high-impact
  - validate_target(), validate_action(), enforce_before_delegation() — Boss must call before delegating
  - Never silently expand scope — default deny
- **Fixed bug:** create_scope had operator precedence bug where authorized_domains provided with target containing :// returned [] — fixed to explicit logic

### 5. Evidence-First Findings (`x19/findings/finding.py`)

- **Finding dataclass:** ID, target, endpoint/component, vuln class (CWE-inspired), severity (CVSS), confidence, repro steps, observed evidence, tool output reference, timestamps, affected agent, verification status, remediation
- **Evidence dataclass:** tool_name, tool_output (real, never fabricated), tool_output_ref, request/response, timestamp, agent_id, endpoint, observation/hypothesis/test/observed_behavior
- **Lifecycle:** CANDIDATE → UNDER_VERIFICATION → VERIFIED or REJECTED (with NEEDS_MORE_EVIDENCE intermediate)
  - Valid transitions enforced
  - Cannot go CANDIDATE → VERIFIED directly (must via UNDER_VERIFICATION)
  - VERIFIED can be re-evaluated as REJECTED (false positive)
  - REJECTED can be re-opened
- **Safety:**
  - can_report_as_verified() only for VERIFIED + HIGH/CONFIRMED confidence (L3/L4)
  - can_report_as_candidate() for CANDIDATE/UNDER_VERIFICATION/NEEDS_MORE_EVIDENCE (L1/L2)
  - Never report rejected as confirmed — enforced in store
  - Every finding must have evidence with tool output — no fabrication
- **FindingStore:** Tracks candidates, verified, rejected separately, stats, persistence via dict

### 6. Anti-Loop / Anti-Waste (`x19/safety/anti_loop.py`)

- **Detects:**
  - Repeated identical commands/tool calls (hash, 5 min window, max 3)
  - No-progress loops
  - Repeated failed hypotheses (hash, max 3)
  - Duplicate tasks (objective+target hash)
  - Stale tasks (running too long without progress, default 10 min)
  - Conflicting conclusions
  - Hallucinated evidence (tool output without ref)
  - Missing evidence (no tool output)
  - Endless recon (no new assets after N iterations, default 2)
  - Identical payloads
- **Strategy:** detect → record failure → change strategy → ask another specialist → escalate to Boss → stop if no productive path
- **FailureRecord:** task_id, agent_id, failure_type, description, evidence, strategy_tried, next_strategy
- **Should stop mission:** Too many high/critical detections in 10 min, or endless recon + no progress
- **Stats:** total_detections, total_failures, by_type, recent_detections

### 7. Mission State (`x19/orchestration/mission_state.py`)

- **MissionState:** Persistent MISSION tree
  - Identity: id, name, created_at, updated_at, created_by
  - Scope: ScopeDefinition
  - Objectives, constraints (time/budget/concurrency)
  - Phase (MissionPhase): SCOPE, PLAN, RECON, ATTACK_SURFACE, HYPOTHESIS, TEST, OBSERVE, CORRELATE, VERIFY, CLASSIFY, REPORT, LEARN, REASSESS, COMPLETED, PAUSED, STOPPED
  - Status (MissionStatus): ACTIVE, PAUSED, STOPPED, COMPLETED, FAILED
  - Agents: agent_id → {role, status, current_task}
  - Tasks: TaskStore (with duplicate prevention)
  - Discoveries: type → list (subdomains, endpoints, tech, etc.)
  - Hypotheses: list with id, vuln_class, endpoint, rationale, status
  - Findings: FindingStore
  - Evidence: list, evidence_dir (gitignored)
  - Blockers: type, description, task_id, agent_id, timestamp, resolved
  - Timeline: timestamp, phase, event, agent, details — real events, not fabricated
  - Anti-loop: AntiLoopDetector
  - Final report, report_path
  - Lessons: type FACT/OBSERVATION/LESSON/SKILL/HYPOTHESIS with provenance, confidence, timestamp
- **Persistence:** save_to_file(), load_from_file() JSON, MissionStateManager with storage_dir (default ~/.hermes/x19/missions or ./x19_missions)
- **Real-time stats:** get_stats() derived from actual runtime state, no mock — agents, tasks, discoveries, hypotheses, findings, blockers, timeline, lessons, anti-loop
- **No mock data:** All status derived from actual mission state

### 8. Task Definitions (`x19/orchestration/task.py`)

- **Task dataclass:** id, mission_id, objective, target, assigned_to (role), assigned_agent_id, scope, allowed/prohibited actions, expected evidence, status (PENDING, ASSIGNED, RUNNING, COMPLETED, FAILED, BLOCKED, CANCELLED), priority, timestamps, progress, evidence, findings, tool_output_refs, failure_reason, retry_count, blocked_reason, requires_approval, dependencies (depends_on, blocks)
- **Lifecycle:** PENDING → ASSIGNED → RUNNING → COMPLETED/FAILED/BLOCKED, with retry logic (max 2 retries)
- **TaskStore:** Duplicate prevention (same objective+target+assigned_to, not failed/cancelled), stats, persistence

### 9. Boss Orchestration (`x19/orchestration/boss.py`)

- **Uses Hermes delegation:** Builds delegate_task args, does NOT create second framework
- **Capabilities:**
  - create_mission() with explicit scope, validates scope
  - decompose_mission() into 7 tasks: Recon, Attack Surface, Hypothesis, Web Test, API Test (parallel), Verification, Reporting — with dependencies and parallel groups
  - assign_tasks() with duplicate prevention
  - get_next_tasks() ready to run (dependencies completed)
  - build_delegation_args() → goal, context, toolsets, role, max_iterations (uses specialist base)
  - handle_task_completion() — update state, add evidence, check phase transition, save
  - handle_task_failure() — record failure, retry or escalate to blocker, anti-loop detection
  - handle_task_blocked() — mark blocked, add blocker
  - get_mission_status() — real-time, no mock
  - Controls: pause_mission(), resume_mission(), stop_mission(), kill_all_tasks() — Operator PAUSE/STOP/KILL ALL/RESET
- **Anti-loop integration:** Records failures, checks should_stop_mission()

### 10. Real-Time Mission Status (`x19/mission/status.py`)

- **get_mission_status():** Derives from actual runtime state, no mock, no fake progress bars
  - Mission ID, name, status, phase, target, timestamps, objectives
  - Agents: total, by_role, active, details
  - Tasks: total, pending, assigned, running, completed, failed, blocked, cancelled
  - Current activity: running/assigned tasks with objective, assigned_to, status, progress
  - Blocked tasks: task_id, objective, blocked_reason, requires_approval
  - Findings: total, candidates, verified, rejected, under_verification, needs_more_evidence, verified_list (top 10), candidate_list (top 10)
  - Discoveries, hypotheses, blockers, timeline_recent, anti_loop, evidence_dir, report_path
- **format_status_for_operator():** Concise text from real state, never fabricated
- **Helpers:**
  - get_whats_happening() — "What's happening?"
  - get_what_completed() — "What has been completed?"
  - get_what_agents_doing() — "What are agents doing?"
  - get_active_tasks() — "Show active tasks"
  - get_findings_summary() — "Show findings" with verified vs candidates vs rejected + evidence

### 11. Human ↔ Boss Interface (`x19/interface/operator.py`)

- **OperatorInterface:** Human ↔ Boss, answers from real mission state, never fabricated
  - start_assessment() → Boss establishes scope, creates mission plan, delegates, returns mission + summary
  - whats_happening() → actual mission state
  - what_completed() → completed tasks, discoveries, verified findings from real runtime
  - what_agents_doing() → running/assigned tasks from real state
  - show_active_tasks() → all tasks from real state
  - show_findings() → candidates, verified, rejected with evidence
  - why_stopped() → blockers, anti-loop, timeline, no-progress detection, strategy change
  - verify_finding() → move to UNDER_VERIFICATION, create verification task for specialist
  - pause(), resume(), stop(), kill_all(), change_scope(), generate_report() — controls, always from real state
  - generate_report() → evidence-based markdown, L3/L4 only for verified, L1/L2 as candidates, never rejected as confirmed, saves to evidence_dir
  - list_missions() → list from storage
- **Uses gateway + CLI infra:** This module provides logic, not transport — integrates with existing Hermes gateway

### 12. Autonomous Security Loop (`x19/loop/loop.py`)

- **Phases in order:** SCOPE → PLAN → RECON → ATTACK_SURFACE → HYPOTHESIS → TEST → OBSERVE → CORRELATE → VERIFY → CLASSIFY → REPORT → LEARN → REASSESS
- **Phase handlers:**
  - SCOPE: Validate scope exists and valid
  - PLAN: Decompose into tasks, assign
  - RECON: Check recon tasks completed, discoveries
  - ATTACK_SURFACE: Build model from discoveries: inputs, tech, auth_flows, subdomains
  - HYPOTHESIS: Check hypotheses exist, pending
  - TEST: Check web/api test tasks
  - OBSERVE: Capture evidence count
  - CORRELATE: Map findings by vuln class
  - VERIFY: Check verification tasks, candidates
  - CLASSIFY: By severity (CVSS)
  - REPORT: Generate evidence-based report via OperatorInterface
  - LEARN: Store lessons with provenance FACT/OBSERVATION/LESSON/SKILL/HYPOTHESIS
  - REASSESS: Check remaining scope, pending/failed/blocked tasks, anti-loop should_stop, should_continue
- **Loop termination:** Scope covered, time/budget exhausted, no productive hypotheses remain, operator stops, anti-loop triggers, no pending tasks
- **Anti-loop:** Integrated, checks should_stop_mission()
- **run_full_loop():** Runs phases in order, max_iterations (default 10), returns iterations, stop_reason, final_phase, final_status
- **Never auto-convert observation to vulnerability:** Enforced via findings lifecycle

### 13. X19 Toolsets (`toolsets.py`)

- **Added 13 X19 toolsets:**
  - x19-recon: terminal, web_search, web_extract, file
  - x19-web: terminal, browser, web, file
  - x19-api: terminal, web, file
  - x19-auth: terminal, browser, web, file
  - x19-cloud: terminal, web, file
  - x19-vuln-research: web, file, skills
  - x19-bugbounty: web, file, skills
  - x19-verification: terminal, browser, web, file
  - x19-evidence: file, todo
  - x19-defensive: terminal, web, file, browser
  - x19-boss: delegation, todo, file, memory
  - x19-manager: delegation, todo, file, terminal, web
  - x19-all: Composite of all X19 toolsets + delegation, todo, file, terminal, web, browser
- **Reuse Hermes tool infrastructure:** No second framework, just tailored toolsets per specialist via ROLE_TOOLSETS

## Tests

- **Created `tests/x19/` with 50 tests, all passing:**
  - test_team_hierarchy.py (11 tests): 11 core roles, 13 total, hierarchy valid, boss/managers orchestrator, specialists leaf, delegation rules, delegation chain, distinct prompts, evidence requirements, hierarchy levels
  - test_scope_control.py (9 tests): scope creation, validation, domain authorization with wildcards, excluded assets, action allowed, high-impact approval, validate target, enforce before delegation, scope summary
  - test_findings.py (7 tests): candidate creation with evidence, lifecycle CANDIDATE→UNDER_VERIFICATION→VERIFIED/REJECTED, invalid transition rejection, evidence required, store tracking, never report rejected as confirmed, repro steps for verified
  - test_mission_state.py (7 tests): mission creation with scope, persistence, status no mock from real runtime, phase transitions, timeline real events, blockers, lessons provenance FACT/OBSERVATION/LESSON/SKILL/HYPOTHESIS
  - test_anti_loop.py (9 tests): repeated command detection, stale task, repeated failed hypothesis, endless recon, identical payload, missing/hallucinated evidence, should stop mission, strategy change suggestion, failure recording
  - test_boss_orchestration.py (7 tests): create mission with explicit scope, decompose into 7 tasks with dependencies and parallel groups (web+api parallel), assign prevents duplicates, get next tasks ready, build delegation args, handle completion, controls pause/resume/stop/kill

- **Hermes baseline preserved:**
  - test_prompt_builder.py::TestBuildContextFilesPrompt::test_empty_dir_loads_seeded_global_soul PASSED (default Hermes mode)
  - is_x19_enabled() now defaults to False (Hermes baseline) unless X19_ENABLED=1 or marker file .x19_mode, X19_MODE, .x19/enabled, x19/enabled, or SOUL.md contains X19 marker
  - Fixed operator precedence bug in create_scope that broke authorized_domains when target contains ://

## Integration with Hermes

- **Reuses existing delegation:** Boss/Managers are orchestrator role (can delegate_task), Specialists are leaf (cannot delegate) — mapped via DELEGATION_ROLE_MAP
- **Reuses toolsets:** X19 toolsets are added to TOOLSETS dict, resolved via existing resolve_toolset()
- **Reuses scope enforcement:** Uses Hermes approval system for high-impact actions (conceptually, enforcement via ScopeEnforcer)
- **Reuses session persistence pattern:** MissionStateManager uses file JSON (similar to hermes_state) with storage_dir default ~/.hermes/x19/missions
- **Preserves Hermes runtime:** No second agent loop, no mock execution, no fake terminal output, no hard-coded findings
- **Identity still opt-in:** is_x19_enabled() defaults False, env X19_ENABLED=1 or marker enables X19 mode — Hermes baseline tests pass

## Safety and Compliance

- **No mock data:** Mission status derived from actual runtime state, no fake progress bars, no decorative animations
- **Evidence-first:** Every finding must have tool output, request/response, timestamp, agent, never fabricated — enforced via Evidence dataclass and check_evidence()
- **Scope control:** Explicit scope required before delegation, Boss enforces, default deny, never silently expand, PAUSE/STOP/KILL ALL/RESET for Operator
- **Lifecycle enforcement:** CANDIDATE → UNDER_VERIFICATION → VERIFIED/REJECTED, never report rejected as confirmed, L3/L4 only for verified, L1/L2 as candidates
- **Anti-loop:** Detect → record failure → change strategy → ask another specialist → escalate → stop
- **Human authority:** Operator retains PAUSE/STOP/KILL ALL/RESET, high-impact requires approval
- **Distinct prompts:** 13 roles with distinct prompt fragments, not 11 copies — verified unique

## Files Created/Modified

- **Created:**
  - x19/team/roles.py (13 roles, distinct prompts)
  - x19/team/hierarchy.py (Boss→Managers→Specialists, delegation rules)
  - x19/team/__init__.py
  - x19/specialists/base.py (build goal/context/config)
  - x19/specialists/boss.py, recon_manager.py, web_manager.py, api_manager.py, web_security.py, api_security.py, auth.py, cloud_infra.py, vuln_research.py, bugbounty_research.py, verification.py, evidence_reporting.py, defensive_validation.py (wrappers)
  - x19/specialists/__init__.py
  - x19/scope/scope.py (ScopeDefinition, ScopeEnforcer, create_scope, validate_scope)
  - x19/scope/__init__.py
  - x19/findings/finding.py (Finding, Evidence, FindingStore, lifecycle)
  - x19/findings/__init__.py
  - x19/safety/anti_loop.py (AntiLoopDetector, LoopType, LoopDetection, FailureRecord)
  - x19/safety/__init__.py
  - x19/orchestration/task.py (Task, TaskStore, TaskStatus, TaskPriority)
  - x19/orchestration/mission_state.py (MissionState, MissionStateManager, MissionPhase, MissionStatus)
  - x19/orchestration/boss.py (BossOrchestrator, DelegationPlan)
  - x19/orchestration/__init__.py
  - x19/mission/status.py (get_mission_status, format_status_for_operator, whats_happening, etc.)
  - x19/mission/__init__.py
  - x19/interface/operator.py (OperatorInterface)
  - x19/interface/__init__.py
  - x19/loop/loop.py (AutonomousSecurityLoop, LoopPhase, LoopState, PHASE_ORDER)
  - x19/loop/__init__.py
  - x19/config/__init__.py
  - tests/x19/test_team_hierarchy.py (11 tests)
  - tests/x19/test_scope_control.py (9 tests)
  - tests/x19/test_findings.py (7 tests)
  - tests/x19/test_mission_state.py (7 tests)
  - tests/x19/test_anti_loop.py (9 tests)
  - tests/x19/test_boss_orchestration.py (7 tests)

- **Modified:**
  - x19/identity/core.py — Fixed is_x19_enabled() to default False (opt-in), marker files checked before config default, SOUL.md marker, raw config file check to avoid DEFAULT_CONFIG False blocking markers
  - x19/__init__.py — Export new modules
  - toolsets.py — Added 13 X19 toolsets (x19-recon, x19-web, x19-api, x19-auth, x19-cloud, x19-vuln-research, x19-bugbounty, x19-verification, x19-evidence, x19-defensive, x19-boss, x19-manager, x19-all)
  - docs/X19_PHASE2_STATUS.md — This file

## Next Steps (Phase 3+)

- **Phase 3 — Specialist Agents:** Enhance specialist prompts with methodology, tool usage examples, evidence collection patterns (already have distinct prompts, but can add more detailed methodology)
- **Phase 4 — Multi-Agent Orchestration:** Integrate Boss orchestration with actual delegate_task tool execution (currently logic layer, needs wiring to real delegation)
- **Phase 5 — Human ↔ Boss Interface:** Wire OperatorInterface to gateway/CLI slash commands (currently logic, needs transport)
- **Phase 6 — Real-Time Mission Status:** Wire status to TUI/CLI dashboard (currently functions, needs UI)
- **Phase 7 — Autonomous Security Loop:** Run loop with real specialists via delegation (currently phase handlers, needs real tool execution)
- **Phase 8 — Anti-Loop:** Already implemented, needs integration with Boss loop
- **Phase 9+ — Knowledge, Datasets, Learning, Skills, Testing:** As per audit

## Verification

```bash
python3 -m pytest tests/x19/ -xvs  # 50 passed
python3 -m pytest tests/agent/test_prompt_builder.py::TestBuildContextFilesPrompt::test_empty_dir_loads_seeded_global_soul -xvs  # PASSED (Hermes baseline)
PYTHONPATH=. python3 -c "from x19.team import validate_team; print(validate_team())"  # (True, [])
PYTHONPATH=. python3 -c "from x19.scope import create_scope, ScopeEnforcer; s=create_scope(target='https://target.com', authorized_domains=['target.com','*.target.com']); e=ScopeEnforcer(s); print(e.is_domain_authorized('sub.target.com'))"  # True
```

**Phase 2 COMPLETE — Security Team Hierarchy implemented, 50 tests passing, Hermes baseline preserved.**
