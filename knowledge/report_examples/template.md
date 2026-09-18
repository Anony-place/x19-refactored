# X19 Security Assessment Report Template

## Executive Summary

- Total findings: {total}
- Verified (L3/L4): {verified}
- Candidates (L1/L2): {candidates}
- Rejected: {rejected}
- Tasks: {tasks}
- Discoveries: {discoveries}

## Scope

Target: {target}
Authorized: {authorized_domains}
Excluded: {excluded_assets}
Allowed actions: {allowed_actions}
Prohibited: {prohibited_actions}

## Verified Findings (L3/L4 — Reportable)

### {finding_id}: {vuln_class} at {endpoint}

- Target: {target}
- Endpoint: {endpoint}
- Component: {component}
- Vuln class: {vuln_class} ({cwe})
- Severity: {severity} (CVSS: {cvss})
- Confidence: {confidence}
- Status: {status}
- Created by: {created_by}
- Verified by: {verified_by}

**Reproduction steps:**

1. {step1}
2. {step2}
3. {step3}

**Observed evidence:**

{observed_evidence}

**Impact:** {impact}

**Remediation:** {remediation}

**Evidence:** {evidence_count} items, tool refs: {tool_output_ref}

**References:** {references}

---

## Candidate Findings (L1/L2 — Pending Verification)

- {finding_id}: {vuln_class} at {endpoint} [{severity}/{confidence}] — {status}

## Rejected Findings

Count: {rejected} (not reported as confirmed)

- {finding_id}: {vuln_class} at {endpoint} — {rejected_reason}

## Timeline

- {timestamp}: [{phase}] {event} ({agent})

## Evidence

Evidence dir: {evidence_dir}
Report path: {report_path}

## Lessons

- {lesson_type}: {content} (provenance: {provenance}, confidence: {confidence})
