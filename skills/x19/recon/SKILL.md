---
name: x19-recon
description: "X19 Recon — asset discovery, endpoint enumeration, tech fingerprint, auth surface (read-only, low-risk) using knowledge base methodology."
version: 1.0.0
author: X19 Team
license: MIT
platforms: [linux, macos]
category: security
triggers:
  - "x19 recon [target]"
  - "asset discovery [target]"
  - "subdomain enum [target]"
  - "endpoint discovery [target]"
toolsets:
  - x19-recon
  - web
  - file
  - terminal
metadata:
  x19:
    tags: [Security, X19, Recon, AssetDiscovery]
---

# X19 Recon

Asset discovery, endpoint enumeration, tech fingerprint, auth surface (read-only, low-risk).

Uses knowledge/methodology/recon.json and knowledge base.

## Methodology

- Subdomain enum: crt.sh via web_search, DNS records, brute force with small wordlist, rate limit 200ms, stop if no new after 2 iterations
- Endpoint discovery: spider via browser, robots.txt, sitemap.xml, JS files for API endpoints, API docs /api/docs, /swagger, /openapi.json, /graphql
- Tech fingerprint: Server header, X-Powered-By, HTML meta, JS libraries, framework-specific paths
- Auth surface: login, registration, password reset, JWT, OAuth, session mapping

## Safety

- Read-only GETs, header analysis, endpoint discovery — low-risk
- Rate limit 200ms per host by default
- No active payloads — recon is read-only
- Stop if endless recon (no new assets after 2 iterations)
- Only authorized domains, respect scope

## Evidence

Every discovered asset must have tool output reference, timestamp, discovery method — no asset without evidence.

## Output

Asset inventory: subdomains, endpoints, tech fingerprint, auth surface, with evidence and tool output references. Feeds attack surface model.
