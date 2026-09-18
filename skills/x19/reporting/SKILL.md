---
name: x19-reporting
description: "X19 Bug Bounty Reporting — evidence-based reports, impact assessment, CVSS, remediation, report quality."
version: 1.0.0
author: X19 Team
license: MIT
platforms: [linux, macos]
category: security
triggers:
  - "x19 report [mission]"
  - "generate bug bounty report"
  - "bug bounty report for [finding]"
toolsets:
  - x19-evidence
  - file
  - todo
  - web
metadata:
  hermes:
    tags: [Security, X19, Reporting, BugBounty]
---

# X19 Bug Bounty Reporting

Bug-bounty methodology, program scope interpretation, report quality, impact assessment.

Uses datasets/bug_bounty/ and knowledge.

## Methodology

- Interpret bug-bounty program scope: authorized targets, exclusions, allowed actions, payout criteria
- Apply bug-bounty methodology: recon → attack surface → hypothesis → test → verify → report
- Assess impact: CVSS 3.1, business impact, exploitability, remediation
- Ensure report quality: repro steps, evidence, impact, remediation, references
- Track program-specific requirements: report format, evidence needed, out-of-scope patterns
- Provide guidance: what bounty programs consider valid, common false positives, triage tips

## Report Quality

- Repro steps: clear, minimal, with evidence
- Impact: CVSS 3.1, business impact, exploitability
- Remediation: specific fix, OWASP, CWE
- Evidence: tool output, request/response, screenshots, timestamps
- References: CWE, OWASP, CVE if applicable

## Safety

- No assuming scope — always verify authorized targets
- No inflating impact without evidence
- No claiming bounty eligibility without verification
