---
name: x19-api-assessment
description: "X19 API Security Assessment — BOLA, BFLA, injection, mass assignment, excessive data exposure with evidence-first."
version: 1.0.0
author: X19 Team
license: MIT
platforms: [linux, macos]
category: security
triggers:
  - "x19 api assessment [target]"
  - "test API [target] for BOLA"
  - "API security test [target]"
toolsets:
  - x19-api
  - terminal
  - web
  - file
metadata:
  x19:
    tags: [Security, X19, API, BOLA, BFLA]
---

# X19 API Security Assessment

Focused API vulnerability testing: BOLA/IDOR, BFLA, injection, mass assignment, excessive data exposure, etc. Evidence-driven.

Uses knowledge/api/ (bola.json, bfla.json) and datasets.

## Methodology

- Test API targets for BOLA/IDOR, BFLA, injection, mass assignment, excessive data exposure
- Use real tools: terminal (curl, httpx), web_search for methodology
- Generate testable hypotheses from API spec/recon, test with witness payloads
- Capture evidence: request/response, tool output, observed behavior
- Distinguish observation vs hypothesis vs evidence vs verified finding
- Report candidates with full evidence

## BOLA Testing

- Auth as user A, get own object ID (e.g., /api/users/me returns id 123)
- Try to access other user's object: /api/users/124 with user A's token
- If returns other user's data, BOLA confirmed — minimal proof, not full PII extraction, redact PII to last 6 chars in chat

## Safety

- No destructive payloads without approval
- No accessing other users' PII beyond minimal proof
- No claiming vuln without evidence
