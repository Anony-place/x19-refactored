# Security-agent patterns tracked for X19 — 2026 Refresh

This document records architecture patterns observed in public projects reviewed for X19. It is a design reference, not copied implementation code. Updated Sep 2026 from Strobes/AppSecSanta/Stingrai/Checkpoint/TechTimes surveys.

## XBOW (web bug-bounty, #1 HackerOne US)

Key patterns: learn→map→coordinate→execute→**independent validator** (zero false positives) + safety SLLM per-action, hypothesis→micro-step exploit chains (longest 48 steps), attack credits (40 light vs full), every packet/log collected → full auditability + treemap per endpoint, reproducible PoC 3-4 steps, WAF bypass via mutation, Bing 2026 RCE 3× CVSS 9.8 via 1-pixel SVG. **X19 borrow:** independent validator + chain PoV re-run + attack credits + treemap (not payload recipes).

## Google Big Sleep (0-day depth, Project Zero×DeepMind)

Key pattern: target codebase → code_browser (follow call graph) → edge-case hypothesis (iColumn=-1) → debugger experiment in python_sandbox → crash=binary oracle → root-cause almost ready-to-report. Tools: code_browser, python_sandbox (fuzz), debugger, reporter. Variant analysis where AFL saturated 150 CPU hrs. CVE-2025-6965 preempted in-the-wild. **X19 borrow:** perfect-verification oracle principle already via 4-gate+OOB; chain-level oracle still needed; variant sweep advisory shipped.

## Team Atlanta Atlantis (AIxCC winner, $4M)

Key patterns: **N-version orthogonal CRS** (C/libafl, Java/Gondar, Multilang), **LLM trust tiers** augmented→opinionated→driven, PoV oracle patch re-run (valid only when PoV fails), fine-tuned Llama-7B beats big model. **X19 borrow:** N-version via fleet+parallel trajectories+failover; trust tiers via deterministic gates + "worker ≠ proof"; PoV re-run needed.

## Shannon (Keygraph, white-box 96.15%)

Key patterns: source-aware static analysis → shortlist vectors → live exploitation (browser+CLI) → PoC per finding with exact source location (Pro correlates static↔dynamic). **X19 borrow:** optional `brain/whitebox_correlator.py` when repo given → world-model edge; keep black-box default.

## Horizon3 NodeZero (graph-based, $2B)

Key patterns: knowledge graph of hosts/services/creds/AD/cloud identities/paths → graph reasoning → specialised agents (Exploit Suggester, High-Value Targeting, Data Pilfering) → deterministic logic prod-safe (310k tests zero disruption) → proof-of-exploit + 1-click Verify. Ephemeral Docker host 2c/8GB, SaaS external. Limit: no SAST/code review (runtime only). **X19 borrow:** graph reasoning + deterministic Verify + 1-click Verify; add AD/cloud nodes.

## PentAGI (microservices harness, 15.5k★)

Key patterns: Go+React+TS, flows→tasks→subtasks→actions, Researcher+Developer+Executor, Docker-Kali sandbox, 20+ tools, GraphQL intensity (recon/normal/aggressive/stealth), 3-layer memory (pgvector+working+episodic) + Neo4j Graphiti KG, observability OTEL→VictoriaMetrics/Jaeger/Loki/Grafana + Langfuse→ClickHouse/Redis/MinIO. **X19 borrow:** flows/tasks queue already via team; need episodic deep + OTEL + Graphiti.

## CAI (Alias Robotics, 300+ backends)

Key pattern: composable agents, 300+ LLM backends, tool gating, ReAct loops, 1k+ commits. Standardizes agentic patterns. **X19 borrow:** provider-agnostic failover + `build_backend` + escalation already parity.

## HexStrike AI v6 (MCP orchestration, 150+ tools)

Key patterns: FastMCP server bridging Claude/GPT/Copilot → 150+ tools (25 net/40 web/20 cloud/25 binary/20 OSINT) as MCP functions, 12+ agents (BugBounty/CTF/CVE/Exploit), Intelligent Decision Engine (tool selection + param opt + chain discovery), execute_command intent→sequenced steps, retry/resilience, smart caching, compact mode for CI. Task in <10min vs days/weeks, parallel 1000s IPs. **X19 borrow:** `execution/mcp_gateway.py` FastMCP server (biggest 2026 gap).

## Strix (prod-ready, score 57)

Key patterns: HTTP proxy manipulation, browser automation, terminal sessions, Python exploit env, CI/CD GitHub Actions, Apache-2.0. CVSS 10 finding, negative quantity 7.1 High. One of 2 tools (with CAI) with banking app actionable results. **X19 borrow:** browser+proxy+terminal exploit env loop-integrated (current BrowserAutomation exists standalone).

## PentestGPT (USENIX 2024)

Key patterns: Reasoning (task-tree) → Generation (commands) → Parsing (noisy output → structured observation). Task-tree persistence. **X19 borrow:** ledger + mission graph + decision_parser already.

## HPTSA (hierarchical, 4.3×)

Key patterns: planning agent (who→when) + task-specific sub-agents (SQLi/XSS...), narrow per-agent context solves context-limit. Proof 4.3× single-agent, zero/one-day 42-47% pass@5. **X19 borrow:** team.py lanes; add narrow per-worker context.

## CyberStrike / Pentest Copilot / HackSynth / pentest-ai-agents (prior refs)

- **CyberStrike:** terminal-native TUI + large skill registry across frameworks → keep terminal primary, expose skill discovery without dashboard chrome.
- **Pentest Copilot:** explicit target/scope intake, autonomous tool loop, tool registry, subagent coordination, browser automation, multiple execution-consent modes → keep deterministic scope gate + visible execution mode/activity.
- **HackSynth:** planner/summarizer separation + benchmark-oriented evaluation → retain compacted context + add repeatable eval fixtures for decision quality/loop avoidance/evidence→finding correctness.
- **pentest-ai-agents:** specialist subagents by domain (recon/web/AD/cloud/mobile/wireless/payloads/exploitation/detection/forensics/reporting) → represent specialists as metadata-driven skills delegated by canonical decision engine.

## X19 design rule (unchanged)

Borrow interfaces and architecture patterns, not payload recipes. Keep all execution behind the existing authorization/policy boundary. The terminal should show real state: target, provider, status, current objective, recent decision, tool activity, coverage, findings, and stop controls. Evidence before finding — validator + oracle are binary, LLM opinion never proof.
