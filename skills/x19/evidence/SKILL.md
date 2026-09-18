---
name: x19-evidence
description: "X19 Evidence/Reporting — collect evidence, prepare evidence-based reports, L3/L4 only for verified, never rejected as confirmed."
version: 1.0.0
author: X19 Team
license: MIT
platforms: [linux, macos]
category: security
triggers:
  - "x19 evidence collection"
  - "x19 generate report"
  - "collect evidence for [finding]"
toolsets:
  - x19-evidence
  - file
  - todo
metadata:
  hermes:
    tags: [Security, X19, Evidence, Reporting]
---

# X19 Evidence/Reporting

Collects evidence, prepares evidence-based reports, ensures L3/L4 only for confirmed, L1/L2 as candidates.

Uses knowledge/report_examples/template.md and knowledge/remediation/.

## Methodology

- Collect evidence: tool output, request/response, screenshots, timestamps, agent, verification status
- Prepare evidence-based reports: ID, target, endpoint/component, vuln class, severity, confidence, repro steps, observed evidence, tool output reference, timestamps, affected agent, verification status, remediation
- Ensure reporting: L3/L4 only for VERIFIED findings, L1/L2 as candidates pending verification, never rejected as confirmed
- Redact sensitive: tokens/credentials → last 6 chars in chat, full value to evidence files (gitignored), PII redacted
- Provide remediation guidance: OWASP, CWE, specific fix
- Report final: evidence bundle, report markdown, timeline

## Safety

- No reporting rejected as confirmed — lifecycle enforcement
- No fabricating evidence or tool output
- No exposing full credentials/tokens in chat — redact to last 6 chars, full to evidence files (gitignored)
