# Top 10 Autonomous Offensive-Security Agents — research notes (Sep 2026)

Research question: kaun se agents **actually dynamically** bugs hunt karte hain
(no hardcoded playbooks), unka workflow kya hai, aur kyu better hai — with the
standing constraint that X19 must copy *patterns and guarantees*, never
hardcoded exploit logic.

Sources: Project Zero blog + coverage (2024–2025), DARPA AIxCC finals reports
(Trail of Bits, aicyberchallenge.com, Team Atlanta blog), 2026 agent-landscape
surveys (appsecsanta, strobes.co, stingrai.io), ARTEMIS paper coverage
(Stanford/CMU/Gray Swan), HackerOne HPSR. Links inline.

---

## 1. Verdict — kaun best, kyu

| Lane | Best | Kyu |
| --- | --- | --- |
| **Web bug-bounty (autonomous, real money)** | **XBOW** | Pehla AI jo global HackerOne leaderboard pe #1 aaya: ~1,060 reports/~90 din (54 critical, 242 high). Loop = hypothesis → micro-step exploit chains → **actual exploitation se validation** + internal reviewer debate. |
| **Deep vulnerability research (real 0-days)** | **Google Big Sleep** | SQLite stack-buffer underflow (Nov 2024, pehla AI-found real-world 0-day), phir **CVE-2025-6965** — threat actors jo exploit ready kar rahe the, Big Sleep ne pehle pakda (first time AI ne in-the-wild exploitation roka), 2025 mein 20 OSS flaws. |
| **Autonomous find-and-patch (competition)** | **Team Atlanta "Atlantis"** | DARPA AIxCC winner ($4M, DEF CON 33): 3 orthogonal CRSs (C/Java/Multilang), fine-tuned Llama-7B, PoV oracle se patch validation; competition ke dauraan **khud 6 SQLite 0-days** nikale. |
| **Open-source harness** | **PentAGI** | ~15.5k stars; Orchestrator+Researcher+Developer+Executor, Docker-Kali sandbox, 3-layer memory, full observability stack. |
| **Benchmark king (white-box web)** | **Shannon (Keygraph / PentestGPT)** | Cleaned, hint-free XBOW benchmark pe **96.15%** (100/104 exploits) — source-code analysis + live exploitation. |

Bottom line: **best overall offensive hunter = XBOW (web bounty) aur Big Sleep
(depth)** — dono ka common denominator neeche section 4 mein hai.

---

## 2. The Top 10 (workflow + proof)

### 1. XBOW — autonomous bug-bounty agent
- **Workflow:** hypothesis form karo → micro-step exploit chain banao (har step
  chhota, verifiable) → real exploitation se validate karo → independent
  internal "reviewer" models se har finding ko debate karwao → report.
- **Proof:** #1 US HackerOne leaderboard (Jun 2025); 54 crit/242 high in 90
  days; novel flaws in Palo Alto GlobalProtect-scale targets.
- **Kyu strong:** volume + validation dono. False positives ko internal debate
  se maarta hai — LLM jo propose karta hai wahi judge nahi hota.
- Founder: Oege de Moor (Semmle/CodeQL/GitHub Copilot lineage).

### 2. Google Big Sleep (Project Zero × DeepMind) — 0-day research
- **Workflow:** codebase browsing (function-call relationships follow karta
  hai) → assertion/edge-case pe interest → "kya ise trigger kiya ja sakta
  hai?" hypothesis → trigger conditions infer → **debugger mein experiment**
  (e.g. `iCol = -1`) → crash = unambiguous proof → root-cause summary.
- **Proof:** SQLite stack buffer underflow (fixed same day, pre-release);
  CVE-2025-6965 preempted from in-the-wild use; ~20 OSS flaws.
- **Kyu strong:** "perfect verification" — success/failure binary (crash ya
  nahi), hallucination execution se marta hai. Variant analysis ko
  cost-effective manual-research replacement bolte hain (fuzzing variants miss
  karti hai).

### 3. Team Atlanta "Atlantis" — AIxCC champion CRS
- **Workflow:** **N-version programming** — multiple independent CRSs
  (Atlantis-C libafl-instrumented directed fuzzer; Atlantis-Java LLM agents +
  coverage-guided "Gondar" fuzzing; Atlantis-Multilang conservative) —
  deliberate orthogonal designs, ek fail ho to doosra chalta hai.
- **LLM trust tiers:** *LLM-augmented* (seed/dict/input generation for
  fuzzers) → *LLM-opinionated* (suggestions = hints, workflow correctness
  preserve karta hai) → *LLM-driven* (autonomous repo navigation for PoV
  blobs). Har tier pe alag trust level — kabhi bhi blind trust nahi.
- **Validation oracle:** PoV (Proof-of-Vulnerability) re-run — patch tabhi
  valid jab PoV fail ho jaye.
- **Kyu strong:** robustness-first engineering + diversity; fine-tuned
  Llama-7B pe domain specialization (C analysis) — "bada model" nahi,
  "sahi-tuned model" jeeta.

### 4. Shannon (Keygraph, PentestGPT repo) — white-box autonomous pentester
- **Workflow:** agentic static analysis (source) → attack-vector shortlist →
  live exploitation with browser + CLI tools → PoC-exploit har finding ke
  saath; Pro edition mein static-dynamic correlation (har vuln ka exact source
  location + working exploit).
- **Proof:** 96.15% on hint-free white-box variant of the XBOW 104-challenge
  benchmark — sabse high published score.
- **Kyu strong:** white-box context (code + runtime) se black-box-only agents
  ko score mein hara deta hai.

### 5. ARTEMIS (Stanford/CMU/Gray Swan) — live-network autonomous agent
- **Study:** 10 human professionals vs 6 AI agents + ARTEMIS on a real
  ~8,000-host network. ARTEMIS: **2nd overall**, 9 valid vulns, **82% valid
  rate**, 10 mein se 9 humans ko beat kiya, ~$59/hr vs ~$60/hr professional.
- **Kyu strong:** pehla credible evidence ki autonomy real networks pe
  cost-competitive hai. Caveat: AI ka false-positive rate humans se higher,
  GUI tasks weak.

### 6. PentAGI — open-source multi-agent harness
- **Workflow:** Orchestrator goal leta hai → Researcher (OSINT/CVE sources) +
  Developer (attack strategy) + Executor (Docker-isolated commands, Kali
  image 20+ tools) → flows→tasks→subtasks→actions hierarchy.
- **Memory:** 3 layers — long-term vector store (pgvector), working context,
  episodic history; Neo4j graph + Langfuse tracing.
- **Kyu strong:** production engineering: sandboxing, observability, REST/GraphQL
  APIs, multi-provider. ~15.5k stars.

### 7. PentestGPT (original, USENIX Security 2024) — reasoning-layer pioneer
- **Workflow (3 modules):** Reasoning (task-tree maintain karta hai, next
  logical step) → Generation (decision → concrete commands) → Parsing (noisy
  tool output → structured observation wapas reasoning module mein).
- **Kyu strong:** academic validation; task-tree = persistent plan state.
  Legacy interactive mode multi-provider; v1.0 autonomous mode Claude-driven.

### 8. HPTSA — hierarchical planner + task agents
- **Workflow:** planning agent (kaunsa sub-agent, kis sequence mein) + multiple
  task-specific sub-agents (SQLi, XSS, …) — **4.3× multi-agent advantage**
  single-agent ke upar; zero-day one-day CVEs pe pass@5 ~42-47% vs single
  agent ~21%.
- **Kyu strong:** hierarchy + specialization ka quantified evidence; paper
  (Fang et al.) ne "agents context limit pe kyu atak jaate hain" bhi diagnose
  kiya — planner narrow context rakh ta hai.

### 9. CAI (Alias Robotics) — build-your-own agent framework
- **Workflow:** composable agents, 300+ LLM backends, tool-use pe focused;
  public bug-bounty submissions claims ke saath.
- **Kyu strong:** framework not product — repeatable agentic patterns
  (ReAct-ish loops, tool gating) standardize karta hai; 1k+ commits, 90+
  contributors.

### 10. VulnBot / xOffense — multi-agent collaborative pentesting
- **Workflow:** 5 modules (Planner, Memory Retriever, Generator, Executor,
  Summarizer) + **Penetration Task Graph** (PTG) — recon→scan→exploit phases
  dependency-ordered; fully open-source models pe chalta hai.
- **Proof:** VulnBot 69.05% subtask (AutoPenBench); **xOffense (refined fork,
  fine-tuned Qwen3-32B) 79.17% sub-task completion — GPT-4 baseline ko beat**
  — domain-tuned mid-scale model > general large model.
- **Kyu strong:** PTG = deterministic task dependencies with LLM reasoning at
  nodes; fine-tuning economics prove karta hai.

**Honourable mentions:** Strix (multi-agent, PoC validation, CVSS 10.0
finding), CHECKMATE (LLM PDDL likhta hai, classical planner solve karta hai —
native LLM agent se 20%+ better, faster & cheaper), NodeZero (network),
HexStrike AI (MCP, 150+ tools), D-CIPHER (44% HTB multi-agent), Anthropic
"Mythos" preview (2026).

---

## 2b. Parity matrix — X19 vs har top agent (code-level, honest verdicts)

Har agent ki **signature capability** → X19 ka counterpart (exact code location)
→ verdict: ✅ parity | ⚠️ partial | ❌ nahi hai. Yeh table claims nahi, code
point karta hai.

| Agent | Signature capability | X19 counterpart | Verdict |
| --- | --- | --- | --- |
| **XBOW** | hypothesis → micro-step exploit chain → real exploitation se validation | ledger (`brain/hypothesis_engine.py`) + chain compass (`brain/exploit_chain.py`) + 4-gate/OOB verification (`agent.py::_validate_finding`, `_poll_oob_oracle`) | ✅ process parity; ⚠️ **chain-level PoV re-run missing** (chains report hote hain bina combined-exploit re-execution ke) |
| **XBOW** | internal reviewer debate (false-positive kill) | `brain/finding_review.py` — hostile second reviewer, critical/high pe mandatory | ✅ |
| **Big Sleep** | iterative hypothesis research + falsifiers | ledger add/test/confirm/reject + pre-registration contract (`tests/test_trajectories.py`) | ✅ |
| **Big Sleep** | debugger/code-browsing verification (white-box) | — X19 black-box hai: OOB oracle + output gates equivalent hain, code-browsing nahi | ⚠️ black-box equivalent only |
| **Big Sleep** | variant analysis | VARIANT CHECK advisory on every confirmation (`agent.py` confirm block) | ✅ |
| **Atlantis** | N-version orthogonal CRSs | fleet units + parallel trajectories + provider failover chain (3 independent "approaches") | ✅ pattern-level |
| **Atlantis** | PoV oracle (patch re-run validation) | X19 patch nahi karta; finding-side oracle = OOB + gates | ⚠️ domain-different |
| **Atlantis** | LLM trust tiers (augmented→opinionated→driven) | deterministic gates + "worker report alone is never proof" boundary | ✅ |
| **ARTEMIS** | live multi-host autonomy + cost/hr | fleet mode (`brain/fleet.py`) + usage ribbon (`_usage_tick`, `X19_PRICE_PER_MTOK`) | ✅ |
| **ARTEMIS** | GUI interaction testing | `tools.BrowserAutomation` MCP/tools se available, loop-integrated nahi | ⚠️ |
| **Shannon** | white-box source↔dynamic correlation | black-box only — repo/artifact context feature nahi | ❌ (roadmap-worthy) |
| **PentAGI** | planner+specialists orchestration | `brain/team.py` boss→managers→workers | ✅ |
| **PentAGI** | Docker-isolated runtimes per agent | policy gateway hai, per-run container isolation nahi | ⚠️ operator responsibility |
| **PentAGI** | layered memory (vector+working+episodic) | Chroma vector + session + failure-memory; **episodic layer thin** | ⚠️ |
| **HPTSA** | hierarchical planner + task agents (4.3×) | team org + lanes | ✅ |
| **HPTSA** | per-agent narrow contexts | ek shared decision context hai; lanes ke worker contexts separate | ⚠️ |
| **PentestGPT** | task-tree persistence + parse/reasoning split | ledger + mission graph + `brain/decision_parser.py` | ✅ |
| **CAI** | backend-agnostic (300+ models) | `providers.py` failover + `build_backend` + escalation chain | ✅ (design parity) |
| **VulnBot/xOffense** | Penetration Task Graph dependencies | mission graph + task queue (`mission.py`, `brain/task_queue.py`) | ✅ |
| **xOffense** | domain-fine-tuned model | operator-choice (provider-agnostic), in-box fine-tuning nahi | ⚠️ n/a |

**Score: 10 ✅ · 8 ⚠️ · 1 ❌** — jahan ⚠️/❌ hai wahan honest reasons hain (black-box
domain, patch-domain difference, ya genuinely missing features: chain-PoV re-run,
white-box correlation, per-run sandboxing, episodic memory depth).

### Is matrix se nikle 4 actionable gaps (priority order)
1. **Chain PoV re-run** (XBOW/Atlantis): chain confirm hone pe combined-exploit
   verification probe dispatch — team lanes iske liye ready hain.
2. **Episodic memory** (PentAGI): per-target run-history ko semantic recall mein
   compounding karna (failure-memory ko vector store se correlate).
3. **Per-run sandboxing** (PentAGI): fleet units ko optional Docker/pod isolation.
4. **White-box correlation** (Shannon): repo/API artifact den pe world-model
   correlation — jab user source share kare.

## 3. Reality check (benchmark honesty)

- CVE-Bench: best framework **13%** zero-day / 25% one-day exploitation of real
  web CVEs — autonomy abhi bhi hard hai.
- Cybench: hardest pro CTF pe sab models ~0%.
- HackerOne: "valid AI report" mostly AI-*assisted*-with-human; pure autonomous
  volume (XBOW) bhi duplicates/informative-heavy.
- ARTEMIS: valid-rate 82% achha, lekin FP rate humans se higher.

---

## 4. Kyu better hai — 9 cross-cutting patterns (X19 ke liye distillation)

1. **Perfect-verification oracle** (Big Sleep PoV/crash, XBOW actual
   exploitation, Atlantis PoV re-run): success binary hona chahiye — LLM ki
   opinion proof nahi. *X19: 4-gate + adversarial review ✓; chain-level PoV
   oracle pending.*
2. **Hypothesis-driven + variant analysis** (Big Sleep): ledger of falsifiable
   ideas; confirmed class ke variants sweep. *X19: research ledger + variant
   advisory ✓ (this is now the same pattern).*
3. **N-version / orthogonal diversity** (Atlantis): ek approach fail → doosra
   survive; coverage bhi badhta hai. *X19 roadmap: parallel independent
   hypothesis trajectories.*
4. **Deterministic orchestration, LLM = reasoning node** (Atlantis tiers,
   CHECKMATE PDDL, VulnBot PTG, Theori constrained workflows): control flow
   code mein, ideas model mein — CHECKMATE ne classical planner se native LLM
   planner ko 20%+ se haraya. *Yehi X19 ka design principle hai — "hardcode
   nahi" ka asli matlab: exploit knowledge hardcode nahi, process guarantees
   hardcode karo.*
5. **Hierarchical multi-agent** (HPTSA 4.3×, PentAGI, pentest-copilot): planner
   context narrow rakhta hai, sub-agents specialize. *X19 roadmap item.*
6. **Layered memory** (PentAGI: vector + working + episodic): X19 mein vector
   (Chroma) + session + failure-memory hai; episodic history layer add-worthy.
7. **White-box × dynamic correlation** (Shannon 96%): source context dena
   benchmark-defining edge hai; X19 black-box hai — API/source artifacts
   milein to world-model mein correlate karna chahiye.
8. **Domain-tuned mid-scale models** (xOffense 79% > GPT-4; Atlantis fine-tuned
   7B): provider-failover ke saath X19 ka "koi bhi backend" design is direction
   mein already flexible hai.
9. **Cost transparency** (ARTEMIS $59/hr): ✅ shipped — ribbon shows
   `N calls ~Tk tok` per run + `~$X` with operator-supplied
   `X19_PRICE_PER_MTOK`; escalations counted separately.

## 5. X19 mapping — kya already hai, kya baaki

| Pattern | X19 status |
| --- | --- |
| LLM-driven commands (no playbook) | ✅ shipped |
| Hypothesis ledger + falsifiers | ✅ shipped (MultiHypothesisEngine wired) |
| Adversarial finding review | ✅ shipped (critical/high) |
| Chain hunting + variant analysis | ✅ shipped |
| Deterministic verification gates | ✅ 4-gate + stale-evidence + HTTP cross-check |
| Parallel hypothesis trajectories | ✅ shipped (pre-registered hypotheses auto-dispatch to team workers; evidence auto-confirm) |
| PoV oracle for chains | ⬜ roadmap (exploit → re-run → binary proof) |
| Hierarchical sub-agents | ✅ shipped (`brain/team.py`: MissionDirector → WorkstreamManager → ProbeWorker, policy-gated) |
| Episodic memory layer | ⬜ roadmap (PentAGI pattern) |
| Fleet (multi-target) | ✅ shipped (`brain/fleet.py`: bounded pool, failure isolation, shared-stack correlation; `x19 fleet` + `/fleet`) |
| OOB callback = blind-vuln oracle | ✅ shipped (`_poll_oob_oracle`: durable evidence + hypothesis correlation + gate integration) |
