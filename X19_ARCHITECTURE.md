# X19 Production Architecture & Cognition Map

This document describes the evolved, production-grade architecture of the **X19 Autonomous Offensive Security Agent**.

---

## 1. System Architecture Diagram

```
                                  ┌─────────────────────────────┐
                                  │      User / WebUI / CLI     │
                                  └──────────────┬──────────────┘
                                                 │
                                                 ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                     X19 AGENT CORE                                          │
│                                       (agent.py)                                            │
│                                                                                             │
│  ┌────────────────────────┐    ┌──────────────────────────┐    ┌─────────────────────────┐  │
│  │    WorldModel Graph    │───>│  MultiHypothesisEngine   │───>│    StrategistEngine     │  │
│  │  (world_model.py)      │    │  (hypothesis_engine.py)  │    │  (strategist_engine.py) │  │
│  └────────────────────────┘    └──────────────────────────┘    └─────────────────────────┘  │
│               ▲                                                             │               │
│               │                                                             ▼               │
│  ┌────────────────────────┐    ┌──────────────────────────┐    ┌─────────────────────────┐  │
│  │    CriticEngine        │<───│    4-Gate Verification   │<───│     Planner Reasoning   │  │
│  │   (critic_engine.py)   │    │  (Observation -> Conf)   │    │      (planner.py)       │  │
│  └────────────────────────┘    └──────────────────────────┘    └─────────────────────────┘  │
└──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                               │
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                ISOLATED EXECUTION GATEWAY                                   │
│  ┌────────────────────────┐    ┌──────────────────────────┐    ┌─────────────────────────┐  │
│  │     CommandGateway     │───>│       ScopeGuard         │───>│      PolicyEngine       │  │
│  │   (command_gateway.py) │    │     (scope_guard.py)     │    │   (policy_engine.py)    │  │
│  └────────────────────────┘    └──────────────────────────┘    └─────────────────────────┘  │
└──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                               │
                                               ▼
                               ┌───────────────────────────────┐
                               │ Target System / Network Layer │
                               └───────────────────────────────┘
```

---

## 2. Key Cognitive Subsystems

### A. WorldModel Knowledge Graph (`brain/world_model.py`)
Maintains real-time structured knowledge of:
- **Hosts & Services:** Open ports, versions, protocols.
- **Endpoints & Tech Stack:** Discovered paths, parameters, frameworks.
- **Authentication Contexts & Credentials:** Active tokens and roles.
- **Attack Paths & Vulnerabilities:** Provenance-tracked vulnerability nodes.

### B. MultiHypothesisEngine (`brain/hypothesis_engine.py`)
Generates and ranks competing hypotheses using multi-dimensional scoring:
$$\text{PriorityScore} = 0.25 \cdot \text{Confidence} + 0.35 \cdot \text{InformationGain} + 0.20 \cdot (1 - \text{Cost}) + 0.20 \cdot (1 - \text{Risk})$$

### C. CriticEngine & Failure Taxonomy (`brain/critic_engine.py`)
Transforms command failures into state penalties and blocks:
- Soft penalties on initial failure.
- Escalating numeric decay on repeated attempts.
- Hard block after 3 consecutive failures to prevent loops.

### D. Hard Scope Guard (`execution/scope_guard.py` & `execution/policy_engine.py`)
Transport and socket-level boundary enforcement preventing out-of-scope traffic or exfiltration redirects.
