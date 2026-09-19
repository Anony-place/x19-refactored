---
name: x19-verification
description: "X19 Exploit Verification — reproduce candidate findings, bypass exhaustion before false-positive dismissal, evidence-first."
version: 1.0.0
author: X19 Team
license: MIT
platforms: [linux, macos]
category: security
triggers:
  - "x19 verify [finding]"
  - "verify finding [id]"
  - "reproduce [vuln] at [endpoint]"
toolsets:
  - x19-verification
  - terminal
  - browser
  - web
  - file
metadata:
  x19:
    tags: [Security, X19, Verification, Exploit]
---

# X19 Exploit Verification

Reproduces candidate findings, confirms or rejects with evidence. Bypass exhaustion before false-positive dismissal.

Uses knowledge/verification/bypass.json and knowledge/false_positive/.

## Methodology

- Reproduce candidate findings with minimal proof, not destructive
- Bypass exhaustion: try alternative payloads, encodings, methods before dismissing as false positive
- Confirm or reject: VERIFIED (with repro steps, evidence) or REJECTED (with reason, failed attempts)
- Capture evidence: request/response, tool output, repro steps, timestamps
- Never auto-reject without trying bypasses; never auto-confirm without reproduction
- Report verification status: UNDER_VERIFICATION → VERIFIED or REJECTED with evidence

## Lifecycle

CANDIDATE → UNDER_VERIFICATION → VERIFIED or REJECTED

## Safety

- No claiming verified without reproduction
- No rejecting without bypass exhaustion
- No destructive reproduction without approval
