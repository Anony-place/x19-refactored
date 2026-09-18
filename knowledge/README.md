# X19 Security Knowledge Base

Public security knowledge from authoritative sources, structured with metadata for X19 autonomous operations.

## Structure

- `web/` - Web vulnerability classes (XSS, SQLi, SSTI, SSRF, XXE, etc.)
- `api/` - API vulnerability classes (BOLA, BFLA, etc.)
- `auth/` - Auth/AuthZ vulnerabilities
- `cloud/` - Cloud/Infra misconfigurations
- `network/` - Network vulnerabilities
- `vuln_classes/` - CWE, CVE mappings, severity classification
- `owasp/` - OWASP Top 10 2021 summary (our own summary, not verbatim)
- `cwe/` - CWE taxonomy summary
- `methodology/` - Recon, testing, verification methodology (OWASP Testing Guide inspired, our synthesis)
- `payloads/` - Public payloads for testing (witness payloads, minimal proof)
- `verification/` - Verification strategies, bypass techniques
- `false_positive/` - Common false positives and identification
- `remediation/` - Remediation guidance per vuln class
- `report_examples/` - Report templates and examples

## Metadata Standard

Every knowledge file must have metadata:
- `source`: authoritative source (e.g., "OWASP Top 10 2021", "CWE", "OWASP Testing Guide")
- `license`: license of source (e.g., "CC BY-SA 4.0", "MIT", "Public Domain")
- `date`: date of knowledge creation/update
- `category`: category (web, api, auth, etc.)
- `confidence`: confidence in knowledge (high, medium, low)
- `provenance`: how knowledge was obtained (e.g., "Synthesized from OWASP Top 10 2021 public documentation")
- `version`: version of knowledge
- `applicable_technologies`: list of technologies where applicable
- `references`: list of reference URLs

## License Compliance

- All knowledge is synthesized in our own words from public authoritative sources
- No verbatim copyrighted text
- Public payloads are common knowledge, not private
- No secrets, PII, credentials, tokens
- Prefer CC BY-SA, MIT, Public Domain licensed sources
- OWASP materials are CC BY-SA 4.0 - we summarize, not copy verbatim
- CWE is public, managed by MITRE

## Usage

Knowledge is loaded via `x19.knowledge` module:
```python
from x19.knowledge import KnowledgeBase
kb = KnowledgeBase()
xss_knowledge = kb.get_vuln_class("xss")
web_methodology = kb.get_methodology("web_testing")
payloads = kb.get_payloads("xss")
```

## Public Sources Used

- OWASP Top 10 2021 (CC BY-SA 4.0) - https://owasp.org/www-project-top-ten/
- CWE Top 25 (MITRE, public) - https://cwe.mitre.org/
- OWASP Testing Guide v4 (CC BY-SA 4.0) - https://owasp.org/www-project-web-security-testing-guide/
- OWASP API Security Top 10 (CC BY-SA 4.0) - https://owasp.org/www-project-api-security/
- Public bug bounty methodology (synthesized from public writeups, no private data)
- Common payloads (public knowledge, e.g., XSS cheat sheets are public domain)
