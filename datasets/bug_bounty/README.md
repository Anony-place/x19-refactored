# X19 Bug Bounty Datasets

Structured bug bounty data with provenance, license checks, PII removal, normalized, deduped, classified.

## Structure

- `methodology.json` - Bug bounty methodology examples (recon, testing, etc.)
- `vuln_examples.json` - Vuln class examples with discovery methodology, evidence pattern, validation, etc.
- `program_patterns.json` - Common program scope patterns
- `metadata.json` - Metadata for datasets

## Metadata Standard

Every dataset file has metadata:
- `source`: source of data (e.g., "Public bug bounty writeups, HackerOne Hacktivity (public), our synthesis")
- `license`: license/terms (e.g., "MIT (our synthesis), public data, no private data")
- `date`: date
- `provenance`: how data was obtained, PII removal, etc.
- `version`: version

## Safety

- No secrets, PII, credentials, tokens
- No private bug bounty reports (only public methodology, our synthesis)
- Normalized, deduped, classified vuln type
- Structured examples: vuln class, affected component, prerequisite, discovery methodology, evidence pattern, validation method, false-positive indicators, impact, remediation, report structure
- All data is synthetic but realistic based on public methodology, not actual private reports

## License Compliance

- Public data, licenses permit use
- Our synthesis is MIT licensed
- No private data, no copyrighted report text
- PII removed, secrets removed

## Usage

Loaded via `x19.datasets` module:
```python
from x19.datasets import BugBountyDatasets
ds = BugBountyDatasets()
methodology = ds.get_methodology()
examples = ds.get_vuln_examples("xss")
```
