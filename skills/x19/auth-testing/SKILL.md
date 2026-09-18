---
name: x19-auth-testing
description: "X19 Auth/AuthZ Testing — auth bypass, IDOR, BOLA, BFLA, privilege escalation, session management with evidence-first."
version: 1.0.0
author: X19 Team
license: MIT
platforms: [linux, macos]
category: security
triggers:
  - "x19 auth test [target]"
  - "test [target] for IDOR"
  - "auth bypass test [target]"
toolsets:
  - x19-auth
  - terminal
  - browser
  - web
  - file
metadata:
  hermes:
    tags: [Security, X19, Auth, IDOR, BOLA]
---

# X19 Auth/AuthZ Testing

Auth bypass, IDOR, BOLA, BFLA, privilege escalation, session management. Evidence-driven.

Uses knowledge/auth/ (idor.json, auth_bypass.json).

## Methodology

- Map auth surface: login, registration, password reset, session, JWT, OAuth
- Test auth/authz: auth bypass, IDOR/BOLA, BFLA, privilege escalation, session fixation, JWT issues
- Use real tools: terminal, browser (auth flows)
- Test with minimal proof: try accessing other user data with own session, not destructive
- Capture evidence: request/response, session handling, observed behavior
- Report candidates with repro steps, impact, remediation

## Safety

- No brute force without explicit approval
- No accessing other users' PII without authorization and minimal proof
- No claiming auth bypass without evidence
