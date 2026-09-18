---
name: x19-web-assessment
description: "X19 Web Security Assessment — XSS, SQLi, SSTI, SSRF, XXE, open redirect, etc. with real tools, witness payloads, evidence-first."
version: 1.0.0
author: X19 Team
license: MIT
platforms: [linux, macos]
category: security
triggers:
  - "x19 web assessment [target]"
  - "test [target] for XSS"
  - "test [target] for SQLi"
  - "web vuln assessment [target]"
toolsets:
  - x19-web
  - terminal
  - browser
  - web
  - file
metadata:
  hermes:
    tags: [Security, X19, Web, XSS, SQLi, SSRF]
---

# X19 Web Security Assessment

Focused web vulnerability testing: XSS, SQLi, SSTI, SSRF, XXE, open redirect, etc. Evidence-driven.

Uses knowledge/web/ (xss.json, sqli.json, ssrf.json, etc.) and knowledge/payloads/.

## Methodology

- Generate testable hypotheses from recon observations
- Test with witness payloads (minimal proof, not destructive): XSS <script>alert(1)</script>, SQLi ' OR 1=1, SSTI {{7*7}}, SSRF http://127.0.0.1
- Capture evidence: request/response, tool output, observed behavior, timestamps
- Distinguish OBSERVATION/HYPOTHESIS/TEST/EVIDENCE/VERIFIED FINDING — never auto-convert observation to vuln
- Report candidates with: target, endpoint, param, vuln class, payload type, observed evidence, tool reference

## Payloads

From knowledge/payloads/ — witness, bypass, context-aware (HTML, attribute, JS, URL), encoding variations.

## Safety

- No destructive payloads without Operator approval
- No claiming vuln without evidence
- No simulating tool output — if tool unavailable: 'Tool unavailable: [tool] not installed'
- Redact tokens to last 6 chars in chat, full to evidence files

## Evidence

Every test: request, response, tool output, timestamp, endpoint, param. Candidate: ID, target, endpoint/component, vuln class, severity (proposed), confidence, repro steps, observed evidence, tool output reference, timestamps, agent, verification status.
