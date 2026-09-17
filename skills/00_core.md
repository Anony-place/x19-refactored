# Skill: recon_surface
**Category:** recon
**Tools:** subfinder, amass, httpx, naabu, nmap
**When:** initial recon, unknown attack surface

## Procedure
1. Run `execution/recon_orchestrator.py` fan-out: subfinder + amass + assetfinder + findomain (12-parallel)
2. Dedup subdomains, httpx live probe, whatweb tech fingerprint
3. naabu top-ports 100 → nmap -sV for open services
4. Persist via `brain/engagement_store.py state_update` and `brain/evo_graph.py`
5. Deposit to `brain/stigmergic_blackboard.py` (subdomain/service pheromones)

# Skill: web_crawl
**Category:** web
**Tools:** katana, httpx, whatweb, browser
**When:** web service discovered

## Procedure
1. katana -u {target} -jc -silent → collect JS endpoints
2. httpx -tech-detect for WAF/tech
3. Browser automation multi-tab (TrafficMind capture)
4. Feed endpoints to world_model + blackboard (endpoint pheromone)

# Skill: vuln_scan
**Category:** vuln
**Tools:** nuclei, dalfox, sqlmap, trafflemind
**When:** endpoints with params discovered

## Procedure
1. nuclei -severity medium,high,critical (185k templates if mounted)
2. dalfox --silence for XSS, sqlmap --batch --level 1 (only with PoC gate)
3. TrafficMind HMAC capture for every payload
4. Report only with PoC (Shannon rule: no PoC → no finding)

# Skill: creds_hunt
**Category:** creds
**Tools:** trufflehog, gitleaks
**When:** repo/files or login forms found

## Procedure
1. trufflehog filesystem {path} --only-verified=false (1060 patterns via RedAMon import)
2. Store creds in EngagementStore credentials table
3. Try credential → access mapping (optional, scope-gated)

# Skill: ad_enum
**Category:** ad
**Tools:** nxc, kerbrute, SharpHound, bloodhound
**When:** AD / SMB / Kerberos service detected

## Procedure
1. nxc smb {target} --users
2. kerbrute userenum --dc {dc} -d {domain}
3. SharpHound collector → BloodHound analysis
4. Requires ScopeGuard pass; do not brute without auth

# Skill: report_and_fix
**Category:** reporting
**Tools:** sarif, autofix
**When:** findings verified

## Procedure
1. reporting/sarif.py → SARIF 2.1.0 (GitHub Code Scanning)
2. reporting/autofix.py triage→group→codefix→draft PR (x19_workspace/autofix/<slug>/DRAFT_PR.md)
3. verify_after_fix via PoV re-run; SARIF diff confirms fix
