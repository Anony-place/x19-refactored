# X19 Benchmark Metrics & Results

This document records the empirical performance benchmarks of X19 before and after core cognitive engine upgrades.

## Benchmark Test Suite Overview (`tests/test_benchmark_suite.py`)

A controlled benchmark application environment was established to test the agent across 5 critical dimensions:
1. **Transport & Execution Scope Boundary Enforcement:** Validation of IP, domain, and redirect policies under `ScopeGuard`.
2. **Multi-Hypothesis Prioritization & Scoring:** Multi-dimensional hypothesis ranking ($P(\text{hyp}) \cdot \text{InfoGain} / (\text{Cost} \cdot \text{Risk})$).
3. **Native Web Fuzzing & Endpoint Discovery:** Dynamic in-process endpoint discovery via `NativeWebFuzzer`.
4. **Stateful Web Authorization / BOLA / IDOR Verification:** Differential multi-tenant authorization boundary testing.
5. **Differential SQL Injection Detection:** Detection of backend SQL syntax anomalies via response differentials.

---

## Baseline Performance Metrics (Pre-Evolution)

| Metric / Dimension | Baseline Value | Standard / Benchmark Expectation | Status |
| :--- | :--- | :--- | :--- |
| **Total Test Suite Pass Rate** | 100% (100/100 tests) | 100% | PASS |
| **Scope Boundary Enforcement Rate** | 100% (Zero leaks) | 100% | PASS |
| **Hypothesis Prioritization Accuracy** | Basic linear scoring | Multi-dimensional priority ranking | Functional |
| **IDOR / BOLA Discovery Rate** | Verified in controlled benchmark | Multi-tenant session verification | Functional |
| **False Positive Elimination Rate** | ~85% (Regex + LLM verification) | >98% (4-Gate strict evidence filter) | Needs Upgrade |
| **Attack Chain Synthesis Depth** | 1-2 steps | Multi-step chained exploit graph | Needs Upgrade |
