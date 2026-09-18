---
name: x19-offensive-team
description: "X19 Autonomous Offensive Team — fully autonomous security operations with Boss→Managers→Specialists hierarchy, knowledge base, payloads, and evidence-first reporting."
version: 1.0.0
author: X19 Team
license: MIT
platforms: [linux, macos]
category: security
triggers:
  - "x19 assess [target]"
  - "x19 autonomous assessment"
  - "start x19 mission"
  - "run x19 offensive team"
  - "x19 full assessment"
  - "autonomous security assessment"
toolsets:
  - x19-all
  - delegation
  - terminal
  - web
  - browser
  - file
  - todo
  - memory
metadata:
  hermes:
    tags: [Security, X19, Autonomous, Offensive, BugBounty, Pentest]
    related_skills: [web-pentest]
---

# X19 Autonomous Offensive Team

Fully autonomous security operations agent built on Hermes foundation. Hierarchical team, evidence-driven, bug-bounty methodology.

## Team Model

```
OPERATOR (human client)
  ↓
X19 BOSS / COMMANDER (you, orchestrator)
  ↓
SECURITY MANAGERS (Recon, Web, API — orchestrator)
  ↓
SPECIALIST AGENTS (9 specialists — leaf)
  ↓
TOOLS / TERMINAL / BROWSER / DATA + KNOWLEDGE BASE + DATASETS
```

Operator talks to Boss. Boss owns mission, defines scope, splits assessment, delegates to Managers, Managers coordinate Specialists, Specialists use real tools + knowledge base + payloads, results return upward with evidence.

## Autonomous Loop

```
SCOPE → PLAN → RECON → ATTACK_SURFACE → HYPOTHESIS → TEST → OBSERVE → CORRELATE → VERIFY → CLASSIFY → REPORT → LEARN → REASSESS
```

- **SCOPE:** Define authorized target, domains/IPs, excluded assets, allowed/prohibited actions, time/budget/concurrency. Boss enforces before delegating. Never silently expand.
- **PLAN:** Decompose into tasks, assign to managers/specialists, define objectives/constraints, parallel groups (web+api parallel)
- **RECON:** Asset discovery, endpoint enumeration, tech fingerprint, auth surface (read-only, low-risk, 200ms rate limit). Use knowledge/methodology/recon.json. Stop if no new assets after 2 iterations (anti-loop).
- **ATTACK_SURFACE:** Map inputs, sinks, trust boundaries, auth flows from recon data. Use offensive methodology.
- **HYPOTHESIS:** Generate testable hypotheses from recon observations using knowledge base (CWE, OWASP, CVE) and datasets. Example: endpoint /search?q= → XSS hypothesis, /api/users/{id} → BOLA hypothesis.
- **TEST:** Execute real tools with witness payloads (minimal proof, not destructive) from knowledge/payloads/. Use PayloadGenerator for context-aware payloads.
- **OBSERVE:** Capture tool output, response behavior, timing, errors as evidence. Evidence must have tool_name, tool_output, request/response, timestamp, agent_id.
- **CORRELATE:** Map observations against known vuln classes (CWE, OWASP, CVE) using knowledge base.
- **VERIFY:** Verification specialist reproduces candidate findings, bypass exhaustion before false-positive dismissal. Lifecycle: CANDIDATE → UNDER_VERIFICATION → VERIFIED or REJECTED.
- **CLASSIFY:** Severity (CVSS 3.1), confidence, impact, remediation using knowledge/remediation/.
- **REPORT:** Evidence-based report, L3/L4 only for VERIFIED (high/confirmed confidence), L1/L2 as candidates pending verification, never rejected as confirmed. Redact tokens to last 6 chars in chat, full to evidence files (gitignored).
- **LEARN:** Store successful/failed workflows, false positives, verification strategies, tool behavior, target context with provenance FACT/OBSERVATION/LESSON/SKILL/HYPOTHESIS. Never allow unverified claims to become permanent knowledge automatically.
- **REASSESS:** Check remaining scope, uncovered areas, new hypotheses from learnings. Loop terminates when scope covered, time/budget exhausted, no productive hypotheses remain, or operator stops.

## Knowledge Base

X19 uses public security knowledge with metadata (source, license, provenance, confidence):

- **OWASP Top 10 2021** (CC BY-SA 4.0): 10 categories, testing approach, remediation
- **CWE Top 25** (Public Domain): CWE IDs, vuln classes, payloads, testing
- **Web vulns:** XSS (reflected/stored/DOM), SQLi (error/boolean/time/union), SSRF, SSTI, XXE, open redirect — methodology, payloads, severity, remediation
- **API vulns:** BOLA/IDOR, BFLA — methodology, evidence pattern, validation
- **Auth:** IDOR, auth bypass — testing, evidence
- **Cloud:** S3 exposure, open ports — recon, testing, safety
- **Network:** CORS misconfig — testing
- **Methodology:** Recon (subdomain enum, endpoint discovery, tech fingerprint, auth surface), Bug bounty (phases, evidence-first, scope enforcement, verification, reporting)
- **Payloads:** Public payloads for XSS, SQLi, SSRF, etc. — witness (minimal proof), bypass (case, encoding), context-aware (HTML, attribute, JS, URL), safety: not destructive
- **Verification:** Bypass techniques per vuln class, verification strategy
- **False Positive:** Common false positives and indicators
- **Remediation:** Remediation guidance per vuln class
- **Report Examples:** Template for evidence-based reporting

Loaded via `x19.knowledge.KnowledgeBase`:
```python
from x19.knowledge import get_knowledge_base
kb = get_knowledge_base()
xss = kb.get_vuln_class("xss")
payloads = kb.get_payloads("xss")
owasp = kb.get_owasp_top10()
```

## Bug Bounty Datasets

Structured data with provenance, license checks, PII removal, normalized, deduped, classified:

- **methodology.json:** Vuln class, affected component, prerequisite, discovery methodology, evidence pattern, validation method, false-positive indicators, impact, remediation, report structure
- **vuln_examples.json:** Synthetic but realistic examples based on public methodology, no private reports, no PII/secrets — ID, vuln class, component, prerequisite, methodology, evidence pattern, validation, impact, remediation, report structure, severity, confidence, CWE, OWASP
- **program_patterns.json:** Common program scope patterns (wildcard_domain, api_scope, mobile_scope, out_of_scope) with interpretation and testing approach
- **metadata.json:** Source, license (MIT), provenance (synthesized from public methodology, no private data, PII removed, secrets removed), safety

Loaded via `x19.datasets.BugBountyDatasets`:
```python
from x19.datasets import get_datasets
ds = get_datasets()
examples = ds.get_vuln_examples("xss")
methodology = ds.get_methodology("bola")
```

## Offensive Capabilities

- **PayloadGenerator:** Witness payloads (minimal proof), bypass payloads (case, encoding), context-aware (HTML, attribute, JS, URL), encoding variations (url, html, double_url, base64, hex, case_random), safety: not destructive, generates payloads for endpoint+param with evidence guidance
- **OffensiveMethodology:** Generate hypotheses from recon observations using knowledge base, build attack surface model (inputs, sinks, trust boundaries, auth flows), prioritize hypotheses by severity, get testing methodology, verification strategy, remediation, false positive indicators per vuln class

## Autonomous Team

`x19.autonomous.AutonomousOffensiveTeam` wires everything together for fully autonomous operation:

```python
from x19.autonomous import AutonomousOffensiveTeam, AutonomousTeamConfig

team = AutonomousOffensiveTeam()
config = AutonomousTeamConfig(
    target="https://target.com",
    authorized_domains=["target.com", "*.target.com"],
    excluded_assets=["/admin"],
    program_name="Test Program",
    objectives=["Assess target.com for OWASP Top 10"],
    max_iterations=5,
    concurrency_limit=3,
    rate_limit_ms=200,
    auto_verify=True,
    auto_report=True
)

mission, msg = team.create_autonomous_mission(config)
results = team.run_autonomous_mission(config, initial_discoveries={
    "subdomains": ["api.target.com"],
    "endpoints": ["/api/users/123", "/search?q=test"],
    "tech": ["nginx", "react"]
})

# Results: mission_id, phases (scope, plan, recon, attack_surface, hypothesis, test, observe, correlate, verify, classify, report, learn, reassess), final_status
```

Team status:
```python
status = team.get_team_status()
# Returns: team, hierarchy, boss, managers, specialists (9), knowledge stats, datasets stats, offensive capabilities, autonomous loop, controls, toolsets
```

## Operator Interface

Operator communicates primarily with Boss, answers from real mission state, never fabricated:

- **Start assessment:** `x19 assess https://target.com` → Boss establishes scope, creates mission plan, delegates
- **What's happening?:** `What's happening?` / `What are agents doing?` / `Show active tasks` → real mission state, current activity from runtime
- **What completed?:** Completed tasks, discoveries, verified findings from real runtime
- **Show findings:** Candidates, verified, rejected with evidence — verified (L3/L4 reportable), candidates (L1/L2 pending), rejected (not reported as confirmed)
- **Why stopped?:** Blockers, no-progress detection, anti-loop, strategy change
- **Verify finding:** `Verify finding X19-ABC123` → verification specialist, UNDER_VERIFICATION
- **Controls:** Pause/Resume/Stop all agents/Change scope/Generate report — always from real state, PAUSE/STOP/KILL ALL/RESET for Operator, high-impact requires approval

Uses `x19.interface.OperatorInterface` and `x19.mission.status` for real-time status, no mock, no fake progress bars.

## Safety

- **No mock data:** Mission status derived from actual runtime state, real tool output flows to mission state
- **Evidence-first:** Every finding must have tool output, request/response, timestamp, agent, never fabricated — lifecycle CANDIDATE→UNDER_VERIFICATION→VERIFIED/REJECTED
- **Scope control:** Explicit scope required before delegation, Boss enforces, default deny, never silently expand, authorized domains/IPs, excluded assets, allowed/prohibited actions, time/budget/concurrency limits
- **Anti-loop:** Detect repeated identical commands/tool calls, no-progress loops, repeated failed hypotheses, duplicate tasks, stale tasks, conflicting conclusions, hallucinated evidence, missing evidence, endless recon → detect → record failure → change strategy → ask another specialist → escalate to Boss → stop if no productive path
- **Human authority:** Operator retains PAUSE/STOP/KILL ALL/RESET, high-impact actions (destructive payloads, auth bypass attempts, cloud metadata probing, production testing) require approval
- **Redaction:** Tokens/credentials → last 6 chars in chat, full value to evidence files (gitignored), other users' PII redacted
- **Learning with provenance:** FACT, OBSERVATION, LESSON, SKILL, HYPOTHESIS separation, provenance, confidence, verified — prevent unverified claims becoming permanent knowledge automatically
- **Rate limiting:** 200ms between active requests per host by default

## Usage Example

```
Operator: x19 assess https://target.com with scope *.target.com, exclude /admin

Boss: Mission accepted: M-ABC123
Target: https://target.com
Scope: target.com, *.target.com, excluded /admin
Tasks created: 7 in 6 parallel groups
Phase: scope
Next: Run recon task via delegation

Boss: [Delegates to Recon Manager]
Recon Manager: Running asset discovery — subdomains via crt.sh, endpoints via spidering, tech via headers
Recon Manager: Discovered: api.target.com, admin.target.com (excluded, skipping), endpoints /api/users, /search, tech nginx, react
Boss: Recon completed: 2 subdomains, 2 endpoints, 2 tech

Boss: [Builds attack surface model]
Boss: Attack surface: 2 endpoints, inputs id, q, url, sinks DOM XSS, SQL, trust boundaries Internet→Web→DB

Boss: [Delegates to Vuln Research Specialist]
Vuln Research: Correlating observations against CWE, OWASP — generated 6 hypotheses: XSS at /search via q, BOLA at /api/users via id, SSRF at /api/fetch via url, etc.
Boss: Hypotheses generated: 6, prioritized: critical (BOLA, SQLi), high (XSS, SSRF), medium (open redirect)

Boss: [Delegates to Web Manager and API Manager in parallel]
Web Manager: Testing XSS at /search via q with witness <script>alert(1)</script> — reflected unescaped, candidate X19-ABC123
API Manager: Testing BOLA at /api/users/123 via id — as user A, GET /api/users/124 returns 200 with other user data (redacted), candidate X19-DEF456
Boss: Testing completed: 2 candidates

Boss: [Delegates to Verification Specialist]
Verification: Reproducing X19-ABC123 with minimal proof — confirmed, bypasses tried, VERIFIED
Verification: Reproducing X19-DEF456 with two accounts — confirmed, VERIFIED
Boss: Verification completed: 2 verified

Boss: [Delegates to Evidence/Reporting Specialist]
Reporter: Preparing evidence-based report — L3/L4 only for verified, L1/L2 as candidates, never rejected as confirmed
Reporter: Report generated: /tmp/x19/missions/M-ABC123_report.md

Boss: Mission completed: 2 verified findings (XSS high, BOLA critical), 0 candidates, 0 rejected, 2 discoveries, 6 hypotheses tested
Operator: Show findings
Boss: [Shows verified vs candidates vs rejected with evidence from real state]
Operator: Generate report
Boss: [Generates evidence-based report from real findings, no mock]
```

## Implementation

- Uses Hermes' existing delegation (`delegate_task` tool), not second framework
- Boss/Managers are orchestrator role (can delegate), Specialists are leaf (cannot delegate)
- Knowledge base and datasets loaded from `knowledge/` and `datasets/bug_bounty/` with metadata
- Payloads from public knowledge, witness minimal proof, not destructive
- Mission state persisted via `x19/orchestration/mission_state.py` (file JSON, similar to hermes_state pattern)
- Real-time status from runtime via `x19/mission/status.py`, no mock
- Autonomous loop via `x19/loop/loop.py` SCOPE→...→REASSESS
- Anti-loop via `x19/safety/anti_loop.py`
- Learning with provenance via `x19/learning/`

## References

- OWASP Top 10 2021 (CC BY-SA 4.0): https://owasp.org/www-project-top-ten/
- CWE Top 25 (Public Domain): https://cwe.mitre.org/top25/
- OWASP Testing Guide v4 (CC BY-SA 4.0): https://owasp.org/www-project-web-security-testing-guide/
- OWASP API Security Top 10 2023 (CC BY-SA 4.0): https://owasp.org/www-project-api-security/
- Public bug bounty methodology (synthesized, no private data)
