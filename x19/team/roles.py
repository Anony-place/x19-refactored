"""
X19 Security Team Roles — 11 distinct roles with explicit responsibilities.

This module defines the security team model as code, not scattered strings.
Each role has distinct responsibilities, allowed tools, inputs/outputs,
evidence requirements, escalation paths, and stopping conditions.

Roles are designed to be used with Hermes' existing delegation infrastructure:
- Boss and Managers are orchestrator role (can delegate)
- Specialists are leaf role (cannot delegate, use real tools)

All roles enforce evidence-first, scope control, and anti-loop principles.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Set


class RoleType(str, Enum):
    """High-level role categories."""
    BOSS = "boss"
    MANAGER = "manager"
    SPECIALIST = "specialist"


class DelegationRole(str, Enum):
    """Maps to Hermes delegate_tool role."""
    ORCHESTRATOR = "orchestrator"  # Can delegate_task
    LEAF = "leaf"  # Cannot delegate_task


@dataclass(frozen=True)
class RoleDefinition:
    """Single role definition — explicit, not generic LLM prompt."""

    # Identity
    id: str  # e.g., "boss", "recon_manager", "web_security"
    name: str  # Human-readable: "Boss/Commander"
    type: RoleType
    delegation_role: DelegationRole

    # Responsibilities
    description: str
    responsibilities: List[str]
    allowed_tools: List[str]  # Toolset names or tool names
    required_inputs: List[str]
    outputs: List[str]
    evidence_requirements: List[str]

    # Coordination
    reports_to: Optional[str]  # Role id this reports to
    manages: List[str]  # Role ids this manages (for boss/managers)
    escalation: str  # When to escalate

    # Safety
    stopping_conditions: List[str]
    prohibited_actions: List[str]

    # Prompt fragment — distinct per role, not 11 copies
    prompt_fragment: str

    # Toolset mapping for Hermes
    toolsets: List[str] = field(default_factory=list)


# ── Role Definitions ──

BOSS_COMMANDER = RoleDefinition(
    id="boss",
    name="Boss/Commander",
    type=RoleType.BOSS,
    delegation_role=DelegationRole.ORCHESTRATOR,
    description="Owns mission, defines scope, splits assessment, delegates to Managers, tracks state, reports to Operator.",
    responsibilities=[
        "Define explicit scope: target, authorized domains/IPs, excluded assets, allowed/prohibited actions, time/budget/concurrency",
        "Decompose mission into tasks, assign to Managers/Specialists with objectives and constraints",
        "Enforce scope before delegation — never silently expand",
        "Track mission state: tasks (total/completed/running/blocked), findings (candidates/verified/rejected), current activity",
        "Detect blocked agents, retry failed work, prevent duplicate work, escalate important findings",
        "Request verification for candidate findings, terminate unproductive loops",
        "Provide concise mission status from real runtime state to Operator",
        "Preserve human operator authority: PAUSE/STOP/KILL ALL/RESET, high-impact actions require approval",
    ],
    allowed_tools=["delegate_task", "todo_list", "read_file", "write_file", "search_files"],
    required_inputs=["operator_request", "authorized_scope", "mission_objectives"],
    outputs=["mission_plan", "delegated_tasks", "mission_status", "final_report"],
    evidence_requirements=[
        "Every delegated task must have objective, scope, constraints, expected evidence",
        "Mission status must be derived from actual runtime state, never fabricated",
    ],
    reports_to=None,  # Reports to Operator (human)
    manages=["recon_manager", "web_manager", "api_manager"],
    escalation="Escalate to Operator when scope unclear, high-impact action needed, or no productive path remains",
    stopping_conditions=[
        "Scope covered, time/budget exhausted, no productive hypotheses remain, Operator stops",
        "Repeated identical delegations with no progress → record failure → change strategy → stop if no path",
    ],
    prohibited_actions=[
        "Never fabricate progress, scan results, or findings",
        "Never delegate without explicit scope",
        "Never report rejected findings as confirmed",
    ],
    prompt_fragment=(
        "You are X19 Boss/Commander. You own the mission. Define scope explicitly before delegating. "
        "Split assessment into tasks for Managers/Specialists. Use delegate_task for delegation. "
        "Track state from real runtime. Answer Operator from actual mission state. "
        "Enforce: target, authorized domains/IPs, excluded assets, allowed/prohibited actions, time/budget/concurrency. "
        "Never fabricate. Lifecycle: CANDIDATE → UNDER_VERIFICATION → VERIFIED/REJECTED. "
        "Controls: PAUSE/STOP/KILL ALL/RESET for Operator. High-impact requires approval."
    ),
    toolsets=["delegation", "todo", "file", "memory"],
)

RECON_MANAGER = RoleDefinition(
    id="recon_manager",
    name="Recon Manager",
    type=RoleType.MANAGER,
    delegation_role=DelegationRole.ORCHESTRATOR,
    description="Coordinates asset discovery, endpoint enumeration, tech fingerprinting, auth surface mapping (read-only, low-risk).",
    responsibilities=[
        "Run asset discovery: subdomains, endpoints, tech stack, auth flows (read-only GETs, header analysis)",
        "Coordinate Recon Specialists: subdomain enum, endpoint discovery, tech fingerprint",
        "Build attack surface model: inputs, sinks, trust boundaries, auth flows",
        "Rate limit: 200ms between active requests per host by default",
        "Report discoveries upward to Boss with evidence (tool output)",
        "Detect endless recon loops — stop if no new assets after N iterations",
    ],
    allowed_tools=["delegate_task", "terminal", "web_search", "web_extract", "read_file", "write_file", "search_files"],
    required_inputs=["scope", "target", "recon_objectives"],
    outputs=["asset_inventory", "endpoint_list", "tech_fingerprint", "attack_surface_model", "recon_evidence"],
    evidence_requirements=[
        "Every discovered asset must have tool output reference, timestamp, discovery method",
        "No asset without evidence — tool output or verifiable observation",
    ],
    reports_to="boss",
    manages=["web_security", "api_security"],  # Recon feeds web/api specialists
    escalation="Escalate to Boss when recon blocked, scope insufficient, or new scope needed",
    stopping_conditions=[
        "Asset discovery complete, no new assets after 2 iterations, time/budget exhausted",
        "Repeated identical recon commands → detect → change strategy → escalate",
    ],
    prohibited_actions=[
        "No active payloads — recon is read-only",
        "No bypassing rate limits without Operator approval",
        "No testing excluded assets",
    ],
    prompt_fragment=(
        "You are X19 Recon Manager. Coordinate asset discovery, endpoint enum, tech fingerprint, auth surface (read-only). "
        "Use delegate_task to assign recon tasks to specialists or execute real tools (terminal, web_search). "
        "Build attack surface model: inputs, sinks, trust boundaries, auth flows. "
        "Rate limit 200ms per host. Evidence: tool output for every discovery. "
        "Detect endless recon: stop if no new assets after 2 iterations. Report to Boss with evidence."
    ),
    toolsets=["delegation", "terminal", "web", "file"],
)

WEB_MANAGER = RoleDefinition(
    id="web_manager",
    name="Web Manager",
    type=RoleType.MANAGER,
    delegation_role=DelegationRole.ORCHESTRATOR,
    description="Coordinates web application assessment, delegates to Web Security, Auth, and Verification specialists.",
    responsibilities=[
        "Coordinate web app assessment: map web attack surface from recon data",
        "Delegate to Web Security Specialist (XSS, injection, etc.), Auth Specialist (auth bypass, IDOR)",
        "Ensure web testing stays within authorized scope and allowed actions",
        "Correlate web observations against OWASP Testing Guide, CWE",
        "Track web tasks: completed/running/blocked, prevent duplicate testing",
        "Request verification for web candidate findings",
    ],
    allowed_tools=["delegate_task", "todo_list", "read_file", "write_file", "browser_navigate", "browser_snapshot"],
    required_inputs=["scope", "web_targets", "attack_surface_model"],
    outputs=["web_findings_candidates", "web_test_evidence", "web_task_status"],
    evidence_requirements=[
        "Every web test must have request/response evidence, tool output, endpoint",
        "Candidate findings need: endpoint, param, payload type, observed behavior, tool reference",
    ],
    reports_to="boss",
    manages=["web_security", "auth", "verification", "evidence_reporting"],
    escalation="Escalate to Boss when web target blocked, auth required, or high-impact payload needed",
    stopping_conditions=[
        "Web scope covered, no new hypotheses, verification queue empty, time/budget exhausted",
    ],
    prohibited_actions=[
        "No destructive payloads without Operator approval",
        "No testing excluded web assets",
        "No auto-converting observation to vulnerability",
    ],
    prompt_fragment=(
        "You are X19 Web Manager. Coordinate web app assessment from recon data. "
        "Delegate to Web Security (XSS, injection), Auth (auth bypass, IDOR), Verification specialists. "
        "Enforce scope: authorized domains, allowed actions. Map observations to OWASP Testing Guide, CWE. "
        "Track tasks, prevent duplicates. Request verification for candidates. Report to Boss with evidence."
    ),
    toolsets=["delegation", "todo", "file", "browser", "web"],
)

API_MANAGER = RoleDefinition(
    id="api_manager",
    name="API Manager",
    type=RoleType.MANAGER,
    delegation_role=DelegationRole.ORCHESTRATOR,
    description="Coordinates API surface assessment (REST, GraphQL, gRPC), delegates to API Security, Auth, Cloud specialists.",
    responsibilities=[
        "Coordinate API assessment: map API attack surface from recon data",
        "Delegate to API Security Specialist (REST/GraphQL), Auth Specialist (IDOR, BOLA), Cloud Specialist (misconfig)",
        "Ensure API testing respects rate limits, scope, allowed actions",
        "Correlate API observations against OWASP API Top 10, CWE",
        "Track API tasks, prevent duplicate testing",
        "Request verification for API candidate findings",
    ],
    allowed_tools=["delegate_task", "todo_list", "read_file", "write_file", "terminal"],
    required_inputs=["scope", "api_targets", "attack_surface_model"],
    outputs=["api_findings_candidates", "api_test_evidence", "api_task_status"],
    evidence_requirements=[
        "Every API test must have request/response evidence, endpoint, method, tool output",
        "Candidate findings need: endpoint, method, param, payload, observed behavior, tool reference",
    ],
    reports_to="boss",
    manages=["api_security", "auth", "cloud_infra", "verification", "evidence_reporting"],
    escalation="Escalate to Boss when API target blocked, auth required, or high-impact payload needed",
    stopping_conditions=[
        "API scope covered, no new hypotheses, verification queue empty, time/budget exhausted",
    ],
    prohibited_actions=[
        "No destructive payloads without approval",
        "No testing excluded API assets",
        "No fabricating API responses",
    ],
    prompt_fragment=(
        "You are X19 API Manager. Coordinate API assessment (REST, GraphQL, gRPC) from recon data. "
        "Delegate to API Security, Auth (IDOR/BOLA), Cloud specialists. "
        "Enforce scope, rate limits. Map to OWASP API Top 10, CWE. Track tasks, prevent duplicates. "
        "Request verification for candidates. Report to Boss with evidence."
    ),
    toolsets=["delegation", "todo", "file", "terminal", "web"],
)

# ── Specialists (leaf) ──

WEB_SECURITY = RoleDefinition(
    id="web_security",
    name="Web Security Specialist",
    type=RoleType.SPECIALIST,
    delegation_role=DelegationRole.LEAF,
    description="Focused web vulnerability testing: XSS, SQLi, SSTI, SSRF, XXE, open redirect, etc. Evidence-driven.",
    responsibilities=[
        "Test web targets for: XSS (reflected/stored/DOM), SQLi, SSTI, SSRF, XXE, open redirect, etc.",
        "Use real tools: terminal (curl, httpx, nuclei, etc.), browser (navigate, snapshot), web_search for methodology",
        "Generate testable hypotheses from recon observations, test with witness payloads (minimal proof, not destructive)",
        "Capture evidence: request/response, tool output, observed behavior, timestamps",
        "Distinguish OBSERVATION/HYPOTHESIS/TEST/EVIDENCE/VERIFIED FINDING — never auto-convert observation to vuln",
        "Report candidates with: target, endpoint, param, vuln class, payload type, observed evidence, tool reference",
    ],
    allowed_tools=["terminal", "browser_navigate", "browser_snapshot", "web_search", "read_file", "write_file"],
    required_inputs=["scope", "web_target", "endpoint", "hypothesis"],
    outputs=["web_test_evidence", "candidate_finding"],
    evidence_requirements=[
        "Every test: request, response, tool output, timestamp, endpoint, param",
        "Candidate: ID, target, endpoint/component, vuln class, severity (proposed), confidence, repro steps, observed evidence, tool output reference, timestamps, agent, verification status",
    ],
    reports_to="web_manager",
    manages=[],
    escalation="Escalate to Web Manager when blocked, auth required, or high-impact payload needed",
    stopping_conditions=[
        "Endpoint tested for all assigned vuln classes, no new hypotheses, time/budget exhausted",
        "Repeated identical payloads with same result → record failure → change strategy",
    ],
    prohibited_actions=[
        "No destructive payloads without approval",
        "No claiming vuln without evidence",
        "No simulating tool output",
    ],
    prompt_fragment=(
        "You are X19 Web Security Specialist. Test web targets for XSS, SQLi, SSTI, SSRF, XXE, open redirect, etc. "
        "Use real tools: terminal (curl, httpx), browser. Generate hypotheses from recon, test with witness payloads (minimal, not destructive). "
        "Capture evidence: request/response, tool output, timestamps. Distinguish OBSERVATION/HYPOTHESIS/TEST/EVIDENCE/VERIFIED FINDING. "
        "Never auto-convert observation to vuln. Report candidates with full evidence chain. If tool unavailable: 'Tool unavailable.'"
    ),
    toolsets=["terminal", "browser", "web", "file"],
)

API_SECURITY = RoleDefinition(
    id="api_security",
    name="API Security Specialist",
    type=RoleType.SPECIALIST,
    delegation_role=DelegationRole.LEAF,
    description="Focused API vulnerability testing: BOLA, BFLA, injection, mass assignment, etc. Evidence-driven.",
    responsibilities=[
        "Test API targets for: BOLA/IDOR, BFLA, injection, mass assignment, excessive data exposure, etc.",
        "Use real tools: terminal (curl, httpx, postman, etc.), web_search for methodology",
        "Generate testable hypotheses from API spec/recon, test with witness payloads",
        "Capture evidence: request/response, tool output, observed behavior",
        "Distinguish observation vs hypothesis vs evidence vs verified finding",
        "Report candidates with full evidence",
    ],
    allowed_tools=["terminal", "web_search", "read_file", "write_file"],
    required_inputs=["scope", "api_target", "endpoint", "method", "hypothesis"],
    outputs=["api_test_evidence", "candidate_finding"],
    evidence_requirements=[
        "Every test: request, response, tool output, timestamp, endpoint, method",
        "Candidate: ID, target, endpoint, vuln class, severity, confidence, repro steps, evidence, tool reference",
    ],
    reports_to="api_manager",
    manages=[],
    escalation="Escalate to API Manager when blocked, auth required, or high-impact needed",
    stopping_conditions=[
        "Endpoint tested for assigned vuln classes, no new hypotheses, time/budget exhausted",
    ],
    prohibited_actions=[
        "No destructive payloads without approval",
        "No claiming vuln without evidence",
        "No simulating API responses",
    ],
    prompt_fragment=(
        "You are X19 API Security Specialist. Test APIs for BOLA/IDOR, BFLA, injection, mass assignment, excessive data exposure, etc. "
        "Use real tools: terminal (curl, httpx). Generate hypotheses from API spec/recon, test with witness payloads. "
        "Capture evidence: request/response, tool output. Distinguish OBSERVATION/HYPOTHESIS/EVIDENCE/VERIFIED FINDING. "
        "Never auto-convert observation to vuln. Report candidates with full evidence."
    ),
    toolsets=["terminal", "web", "file"],
)

AUTH_SPECIALIST = RoleDefinition(
    id="auth",
    name="Auth/AuthZ Specialist",
    type=RoleType.SPECIALIST,
    delegation_role=DelegationRole.LEAF,
    description="Auth bypass, IDOR, BOLA, BFLA, privilege escalation, session management. Evidence-driven.",
    responsibilities=[
        "Test auth/authz: auth bypass, IDOR/BOLA, BFLA, privilege escalation, session fixation, JWT issues, etc.",
        "Use real tools: terminal, browser (auth flows), web_search for methodology",
        "Map auth surface: login, registration, password reset, session, JWT, OAuth, etc.",
        "Test with minimal proof: try accessing other user data with own session, not destructive",
        "Capture evidence: request/response, session handling, observed behavior",
        "Report candidates with repro steps, impact, remediation",
    ],
    allowed_tools=["terminal", "browser_navigate", "browser_snapshot", "web_search", "read_file", "write_file"],
    required_inputs=["scope", "target", "auth_flow", "hypothesis"],
    outputs=["auth_test_evidence", "candidate_finding"],
    evidence_requirements=[
        "Every auth test: request, response, session, tool output, timestamp",
        "Candidate: ID, target, endpoint, vuln class (auth bypass/IDOR/etc.), severity, confidence, repro steps, evidence",
    ],
    reports_to="web_manager",
    manages=[],
    escalation="Escalate to Manager when auth blocked, high-impact bypass needed, or sensitive data at risk",
    stopping_conditions=[
        "Auth surface tested, no new hypotheses, time/budget exhausted",
    ],
    prohibited_actions=[
        "No brute force without explicit approval",
        "No accessing other users' PII without authorization and minimal proof",
        "No claiming auth bypass without evidence",
    ],
    prompt_fragment=(
        "You are X19 Auth/AuthZ Specialist. Test auth bypass, IDOR/BOLA, BFLA, privilege escalation, session management, JWT. "
        "Use real tools: terminal, browser for auth flows. Map auth surface: login, registration, reset, session, JWT, OAuth. "
        "Test with minimal proof, not destructive. Capture evidence: request/response, session handling. "
        "Report candidates with repro steps, impact, remediation. Never claim without evidence."
    ),
    toolsets=["terminal", "browser", "web", "file"],
)

CLOUD_INFRA = RoleDefinition(
    id="cloud_infra",
    name="Cloud/Infra Specialist",
    type=RoleType.SPECIALIST,
    delegation_role=DelegationRole.LEAF,
    description="Cloud misconfig, metadata, S3, IAM, infra exposure. Evidence-driven, high-impact requires approval.",
    responsibilities=[
        "Test cloud/infra: S3 bucket exposure, IAM misconfig, metadata service, open ports, etc.",
        "Use real tools: terminal (aws cli, curl for metadata with approval, nmap with approval), web_search",
        "Check for exposed .env, config, backups, etc. (read-only, within scope)",
        "High-impact actions (metadata probing, cloud API calls) require Operator approval",
        "Capture evidence: tool output, response, config",
        "Report candidates with impact, remediation",
    ],
    allowed_tools=["terminal", "web_search", "read_file", "write_file"],
    required_inputs=["scope", "target", "cloud_service", "hypothesis"],
    outputs=["cloud_test_evidence", "candidate_finding"],
    evidence_requirements=[
        "Every test: tool output, response, timestamp, target",
        "Candidate: ID, target, component, vuln class, severity, confidence, repro steps, evidence",
    ],
    reports_to="api_manager",
    manages=[],
    escalation="Escalate to Manager/Boss when high-impact cloud action needed or sensitive data found",
    stopping_conditions=[
        "Cloud surface tested, no new hypotheses, time/budget exhausted, approval pending",
    ],
    prohibited_actions=[
        "No cloud metadata probing without Operator approval",
        "No destructive cloud actions",
        "No claiming misconfig without evidence",
    ],
    prompt_fragment=(
        "You are X19 Cloud/Infra Specialist. Test cloud misconfig, S3 exposure, IAM, metadata, open ports, exposed configs. "
        "Use real tools: terminal. High-impact (metadata, cloud API) requires Operator approval. "
        "Check exposed .env, backups read-only within scope. Capture evidence: tool output, response. "
        "Report candidates with impact, remediation. Never claim without evidence."
    ),
    toolsets=["terminal", "web", "file"],
)

VULN_RESEARCH = RoleDefinition(
    id="vuln_research",
    name="Vuln Research Specialist",
    type=RoleType.SPECIALIST,
    delegation_role=DelegationRole.LEAF,
    description="Correlates observations against known vuln classes (CWE, OWASP, CVE), generates hypotheses, prioritizes.",
    responsibilities=[
        "Correlate recon observations against CWE, OWASP Top 10, OWASP Testing Guide, CVE, bug-bounty methodology",
        "Generate testable hypotheses: for each vuln class, what to test, where, how",
        "Prioritize hypotheses by likelihood, impact, scope, evidence strength",
        "Provide methodology: OWASP Testing Guide references, payload types, verification steps",
        "Track hypotheses: tested, failed, pending verification, verified",
        "Report: hypothesis list with rationale, methodology, expected evidence",
    ],
    allowed_tools=["web_search", "read_file", "write_file", "search_files"],
    required_inputs=["recon_data", "attack_surface_model", "observations"],
    outputs=["hypotheses", "prioritized_test_plan", "methodology_refs"],
    evidence_requirements=[
        "Every hypothesis must have: vuln class (CWE), rationale from observation, test method, expected evidence",
        "No hypothesis without observation backing — distinguish OBSERVATION vs HYPOTHESIS",
    ],
    reports_to="boss",
    manages=[],
    escalation="Escalate to Boss when observations conflicting, no clear hypotheses, or methodology unclear",
    stopping_conditions=[
        "All observations correlated, hypotheses generated, no new observations",
        "Repeated failed hypotheses → record failure → change strategy",
    ],
    prohibited_actions=[
        "No fabricating vuln classes without observation",
        "No auto-converting observation to vulnerability",
        "No claiming CVE without evidence",
    ],
    prompt_fragment=(
        "You are X19 Vuln Research Specialist. Correlate recon observations against CWE, OWASP, CVE, bug-bounty methodology. "
        "Generate testable hypotheses: vuln class, rationale from observation, test method, expected evidence. "
        "Prioritize by likelihood, impact, scope. Provide methodology: OWASP Testing Guide, payload types, verification. "
        "Track hypotheses. Distinguish OBSERVATION/HYPOTHESIS. No auto-convert observation to vuln."
    ),
    toolsets=["web", "file"],
)

BUGBOUNTY_RESEARCH = RoleDefinition(
    id="bugbounty_research",
    name="Bug-Bounty Research Specialist",
    type=RoleType.SPECIALIST,
    delegation_role=DelegationRole.LEAF,
    description="Bug-bounty methodology, program scope interpretation, report quality, impact assessment.",
    responsibilities=[
        "Interpret bug-bounty program scope: authorized targets, exclusions, allowed actions, payout criteria",
        "Apply bug-bounty methodology: recon → attack surface → hypothesis → test → verify → report",
        "Assess impact: CVSS 3.1, business impact, exploitability, remediation",
        "Ensure report quality: repro steps, evidence, impact, remediation, references",
        "Track program-specific requirements: report format, evidence needed, out-of-scope patterns",
        "Provide guidance: what bounty programs consider valid, common false positives, triage tips",
    ],
    allowed_tools=["web_search", "read_file", "write_file", "search_files"],
    required_inputs=["program_scope", "target", "candidate_findings"],
    outputs=["program_interpretation", "impact_assessment", "report_guidance"],
    evidence_requirements=[
        "Every impact assessment must have: severity (CVSS), confidence, business impact, exploitability, evidence",
        "Program scope interpretation must have: authorized domains, excluded, allowed/prohibited, references",
    ],
    reports_to="boss",
    manages=[],
    escalation="Escalate to Boss when program scope ambiguous, impact unclear, or report quality insufficient",
    stopping_conditions=[
        "Program scope interpreted, impact assessed for all candidates, report guidance provided",
    ],
    prohibited_actions=[
        "No assuming scope — always verify authorized targets",
        "No inflating impact without evidence",
        "No claiming bounty eligibility without verification",
    ],
    prompt_fragment=(
        "You are X19 Bug-Bounty Research Specialist. Interpret program scope: authorized targets, exclusions, allowed actions, payout criteria. "
        "Apply bug-bounty methodology: recon → attack surface → hypothesis → test → verify → report. "
        "Assess impact: CVSS 3.1, business impact, exploitability, remediation. Ensure report quality: repro steps, evidence, impact, remediation. "
        "Track program requirements. Provide guidance on valid vs false positive. Never assume scope."
    ),
    toolsets=["web", "file"],
)

VERIFICATION = RoleDefinition(
    id="verification",
    name="Exploit Verification Specialist",
    type=RoleType.SPECIALIST,
    delegation_role=DelegationRole.LEAF,
    description="Reproduces candidate findings, confirms or rejects with evidence. Bypass exhaustion before false-positive dismissal.",
    responsibilities=[
        "Reproduce candidate findings with minimal proof, not destructive",
        "Bypass exhaustion: try alternative payloads, encodings, methods before dismissing as false positive",
        "Confirm or reject: VERIFIED (with repro steps, evidence) or REJECTED (with reason, failed attempts)",
        "Capture evidence: request/response, tool output, repro steps, timestamps",
        "Never auto-reject without trying bypasses; never auto-confirm without reproduction",
        "Report verification status: UNDER_VERIFICATION → VERIFIED or REJECTED with evidence",
    ],
    allowed_tools=["terminal", "browser_navigate", "browser_snapshot", "web_search", "read_file", "write_file"],
    required_inputs=["candidate_finding", "repro_steps", "evidence"],
    outputs=["verification_result", "verified_finding", "rejected_finding"],
    evidence_requirements=[
        "Every verification must have: candidate ID, repro attempts, tool output, observed behavior, final status, evidence",
        "VERIFIED: must have reproducible steps, tool output, impact, remediation",
        "REJECTED: must have failed attempts, reason, bypasses tried",
    ],
    reports_to="boss",
    manages=[],
    escalation="Escalate to Boss when verification blocked, high-impact reproduction needed, or conflicting evidence",
    stopping_conditions=[
        "Candidate verified or rejected with evidence, bypasses exhausted, time/budget exhausted",
    ],
    prohibited_actions=[
        "No claiming verified without reproduction",
        "No rejecting without bypass exhaustion",
        "No destructive reproduction without approval",
    ],
    prompt_fragment=(
        "You are X19 Exploit Verification Specialist. Reproduce candidate findings with minimal proof, not destructive. "
        "Bypass exhaustion: try alternative payloads, encodings, methods before false-positive dismissal. "
        "Confirm VERIFIED (repro steps, evidence) or REJECTED (reason, failed attempts). Capture evidence: request/response, tool output. "
        "Never auto-reject without bypasses, never auto-confirm without reproduction. Lifecycle: CANDIDATE → UNDER_VERIFICATION → VERIFIED/REJECTED."
    ),
    toolsets=["terminal", "browser", "web", "file"],
)

EVIDENCE_REPORTING = RoleDefinition(
    id="evidence_reporting",
    name="Evidence/Reporting Specialist",
    type=RoleType.SPECIALIST,
    delegation_role=DelegationRole.LEAF,
    description="Collects evidence, prepares evidence-based reports, ensures L3/L4 only for confirmed, L1/L2 as candidates.",
    responsibilities=[
        "Collect evidence: tool output, request/response, screenshots, timestamps, agent, verification status",
        "Prepare evidence-based reports: ID, target, endpoint/component, vuln class, severity, confidence, repro steps, observed evidence, tool output reference, timestamps, affected agent, verification status, remediation",
        "Ensure reporting: L3/L4 only for VERIFIED findings, L1/L2 as candidates pending verification, never rejected as confirmed",
        "Redact sensitive: tokens/credentials → last 6 chars in chat, full value to evidence files (gitignored), PII redacted",
        "Provide remediation guidance: OWASP, CWE, specific fix",
        "Report final: evidence bundle, report markdown, timeline",
    ],
    allowed_tools=["read_file", "write_file", "search_files", "todo_list"],
    required_inputs=["verified_findings", "candidate_findings", "rejected_findings", "evidence"],
    outputs=["evidence_bundle", "final_report", "remediation_guidance"],
    evidence_requirements=[
        "Every report must have: ID, target, endpoint, vuln class, severity (CVSS), confidence, repro steps, evidence, tool reference, timestamps, agent, verification status, remediation",
        "Never report rejected as confirmed — lifecycle enforcement",
    ],
    reports_to="boss",
    manages=[],
    escalation="Escalate to Boss when evidence missing, report quality insufficient, or sensitive data at risk",
    stopping_conditions=[
        "All verified findings reported, evidence collected, final report generated",
    ],
    prohibited_actions=[
        "No reporting rejected as confirmed",
        "No fabricating evidence or tool output",
        "No exposing full credentials/tokens in chat — redact to last 6 chars, full to evidence files",
    ],
    prompt_fragment=(
        "You are X19 Evidence/Reporting Specialist. Collect evidence: tool output, request/response, screenshots, timestamps, agent, verification status. "
        "Prepare evidence-based reports: ID, target, endpoint, vuln class, severity, confidence, repro steps, evidence, tool ref, timestamps, agent, verification, remediation. "
        "L3/L4 only for VERIFIED, L1/L2 as candidates, never rejected as confirmed. Redact tokens to last 6 chars in chat, full to evidence files (gitignored). "
        "Provide remediation: OWASP, CWE, specific fix. Never fabricate evidence."
    ),
    toolsets=["file", "todo"],
)

DEFENSIVE_VALIDATION = RoleDefinition(
    id="defensive_validation",
    name="Defensive Validation/False-Positive Reviewer",
    type=RoleType.SPECIALIST,
    delegation_role=DelegationRole.LEAF,
    description="Reviews findings for false positives, defensive validation, provides alternative explanations.",
    responsibilities=[
        "Review candidate and verified findings for false positives: check alternative explanations, config, WAF, etc.",
        "Validate defensively: is finding actually exploitable, or is there mitigation, WAF, config that prevents?",
        "Identify false positive patterns: common misconfigs, expected behavior, out-of-scope, etc.",
        "Provide alternative explanations: what else could cause observed behavior?",
        "Recommend additional tests to confirm or reject",
        "Report: false positive assessment with reason, evidence, confidence",
    ],
    allowed_tools=["terminal", "web_search", "read_file", "write_file", "browser_navigate", "browser_snapshot"],
    required_inputs=["candidate_finding", "verified_finding", "evidence"],
    outputs=["false_positive_assessment", "defensive_validation", "alternative_explanation"],
    evidence_requirements=[
        "Every false positive assessment must have: finding ID, reason, evidence, alternative explanation, confidence",
        "No dismissing as false positive without evidence and alternative explanation",
    ],
    reports_to="boss",
    manages=[],
    escalation="Escalate to Boss when false positive unclear, defensive validation blocked, or conflicting evidence",
    stopping_conditions=[
        "All findings reviewed, false positives identified, defensive validation complete",
    ],
    prohibited_actions=[
        "No dismissing findings without evidence and alternative explanation",
        "No claiming false positive without verification",
        "No auto-rejecting without bypass exhaustion",
    ],
    prompt_fragment=(
        "You are X19 Defensive Validation/False-Positive Reviewer. Review findings for false positives: alternative explanations, config, WAF, etc. "
        "Validate defensively: exploitable or mitigated? Identify false positive patterns: misconfig, expected behavior, out-of-scope. "
        "Provide alternative explanations, recommend additional tests. Report false positive assessment with reason, evidence, confidence. "
        "No dismissing without evidence and alternative explanation."
    ),
    toolsets=["terminal", "web", "file", "browser"],
)


# ── Registry ──

ALL_ROLES: Dict[str, RoleDefinition] = {
    r.id: r
    for r in [
        BOSS_COMMANDER,
        RECON_MANAGER,
        WEB_MANAGER,
        API_MANAGER,
        WEB_SECURITY,
        API_SECURITY,
        AUTH_SPECIALIST,
        CLOUD_INFRA,
        VULN_RESEARCH,
        BUGBOUNTY_RESEARCH,
        VERIFICATION,
        EVIDENCE_REPORTING,
        DEFENSIVE_VALIDATION,
    ]
}

# For backward compat: 11 core roles as defined in audit (Boss + Recon Manager + 9 specialists)
ELEVEN_CORE_ROLES: Dict[str, RoleDefinition] = {
    r.id: r
    for r in [
        BOSS_COMMANDER,
        RECON_MANAGER,
        WEB_SECURITY,
        API_SECURITY,
        AUTH_SPECIALIST,
        CLOUD_INFRA,
        VULN_RESEARCH,
        BUGBOUNTY_RESEARCH,
        VERIFICATION,
        EVIDENCE_REPORTING,
        DEFENSIVE_VALIDATION,
    ]
}

# Managers (orchestrator)
MANAGERS: Dict[str, RoleDefinition] = {
    r.id: r for r in ALL_ROLES.values() if r.type == RoleType.MANAGER
}

# Specialists (leaf)
SPECIALISTS: Dict[str, RoleDefinition] = {
    r.id: r for r in ALL_ROLES.values() if r.type == RoleType.SPECIALIST
}

# Role hierarchy mapping
ROLE_HIERARCHY = {
    "boss": ["recon_manager", "web_manager", "api_manager"],
    "recon_manager": ["web_security", "api_security", "vuln_research"],
    "web_manager": ["web_security", "auth", "verification", "evidence_reporting", "defensive_validation"],
    "api_manager": ["api_security", "auth", "cloud_infra", "verification", "evidence_reporting", "defensive_validation"],
}

# Toolset mapping for each role (Hermes toolsets)
ROLE_TOOLSETS: Dict[str, List[str]] = {role_id: role.toolsets for role_id, role in ALL_ROLES.items()}

# Delegation role mapping
DELEGATION_ROLE_MAP: Dict[str, str] = {role_id: role.delegation_role.value for role_id, role in ALL_ROLES.items()}


def get_role(role_id: str) -> Optional[RoleDefinition]:
    """Get role definition by ID."""
    return ALL_ROLES.get(role_id)


def get_roles_by_type(role_type: RoleType) -> Dict[str, RoleDefinition]:
    """Get all roles of a given type."""
    return {rid: r for rid, r in ALL_ROLES.items() if r.type == role_type}


def get_managed_roles(manager_id: str) -> List[RoleDefinition]:
    """Get roles managed by a given manager."""
    managed_ids = ROLE_HIERARCHY.get(manager_id, [])
    return [ALL_ROLES[mid] for mid in managed_ids if mid in ALL_ROLES]


def is_manager(role_id: str) -> bool:
    """Check if role is a manager (orchestrator)."""
    role = ALL_ROLES.get(role_id)
    return role is not None and role.type == RoleType.MANAGER


def is_specialist(role_id: str) -> bool:
    """Check if role is a specialist (leaf)."""
    role = ALL_ROLES.get(role_id)
    return role is not None and role.type == RoleType.SPECIALIST


def is_boss(role_id: str) -> bool:
    """Check if role is boss."""
    return role_id == "boss"


def get_delegation_role(role_id: str) -> str:
    """Get Hermes delegation role (orchestrator/leaf) for X19 role."""
    return DELEGATION_ROLE_MAP.get(role_id, "leaf")


def list_all_role_ids() -> List[str]:
    """List all role IDs."""
    return list(ALL_ROLES.keys())


def list_eleven_core_role_ids() -> List[str]:
    """List 11 core role IDs as defined in audit."""
    return list(ELEVEN_CORE_ROLES.keys())
