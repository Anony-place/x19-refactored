#!/usr/bin/env python3
"""Cognitive Brain Verification Test for X19 Migration.

This test verifies that the new cognitive subsystems work correctly:
1. Evidence Ranking Engine
2. Multi-Hypothesis Engine  
3. Attack Graph Engine

Runtime Validation Scenario:
- Target with 22/tcp OpenSSH
- 80/tcp nginx
- Exposed .git
- Git commit history
- Developer credentials

Expected behavior:
- Does NOT perform another generic Nmap scan
- Does NOT attempt interactive SSH
- Prioritizes exposed repository
- Updates attack graph
- Generates multiple hypotheses
- Justifies chosen path
- Rejects weaker hypotheses
"""

import sys
sys.path.insert(0, '/workspace')

from brain.evidence_ranking import EvidenceRankingEngine, RankedEvidence, EvidenceScore
from brain.hypothesis_engine import MultiHypothesisEngine
from brain.attack_graph import AttackGraph, NODE_SERVICE, NODE_ENDPOINT, NODE_CREDENTIAL


def test_evidence_ranking():
    """Test the Evidence Ranking Engine."""
    print("=" * 60)
    print("TEST 1: EVIDENCE RANKING ENGINE")
    print("=" * 60)
    
    engine = EvidenceRankingEngine()
    
    # Simulate discovered evidence from scenario
    evidence_items = [
        # Port 22 - SSH
        RankedEvidence(
            id="port_22",
            source="nmap",
            kind="port",
            data={"port": 22, "service": "ssh", "proto": "tcp"}
        ),
        # Port 80 - HTTP
        RankedEvidence(
            id="port_80",
            source="nmap",
            kind="port",
            data={"port": 80, "service": "http", "proto": "tcp"}
        ),
        # .git endpoint - HIGH VALUE
        RankedEvidence(
            id="endpoint_git",
            source="gobuster",
            kind="endpoint",
            data={"url": "/.git/config", "method": "GET", "status": 200}
        ),
        # Generic endpoint - lower value
        RankedEvidence(
            id="endpoint_index",
            source="gobuster",
            kind="endpoint",
            data={"url": "/index.html", "method": "GET", "status": 200}
        ),
    ]
    
    # Add evidence and calculate scores
    model_state = {"ports": [{"port": 22}, {"port": 80}], "endpoints": [], "credentials": []}
    
    for ev in evidence_items:
        # Calculate information gain
        ev.score.information_gain = engine.calculate_information_gain(ev, model_state)
        
        # Calculate exploitability
        ev.score.exploitability = engine.calculate_exploitability(ev)
        
        # Calculate dependency value
        ev.score.dependency_value = engine.calculate_dependency_value(ev)
        
        # Set base confidence
        ev.score.confidence = 0.8 if ev.data.get('status', 0) == 200 else 0.5
        
        # Set novelty (first time seeing these)
        ev.score.novelty = 1.0
        
        # Set mission impact (.git is high impact)
        if '.git' in str(ev.data):
            ev.score.mission_impact = 0.95
        elif ev.kind == "port":
            ev.score.mission_impact = 0.6
        else:
            ev.score.mission_impact = 0.4
        
        # Set uncertainty
        ev.score.uncertainty = 0.2 if ev.data.get('status', 0) == 200 else 0.5
        
        engine.add_evidence(ev)
    
    # Get ranked evidence
    ranked = engine.get_ranked_evidence(limit=10)
    
    print("\nRanked Evidence (by total_score):")
    print("-" * 60)
    for i, ev in enumerate(ranked, 1):
        print(f"{i}. [{ev.kind}] {ev.summary}")
        print(f"   Total Score: {ev.score.total_score:.3f}")
        print(f"   Breakdown: conf={ev.score.confidence:.2f}, gain={ev.score.information_gain:.2f}, "
              f"exploit={ev.score.exploitability:.2f}, dep={ev.score.dependency_value:.2f}, "
              f"impact={ev.score.mission_impact:.2f}, novelty={ev.score.novelty:.2f}")
        print()
    
    # Verify .git endpoint is ranked highest
    top_evidence = ranked[0]
    assert '.git' in str(top_evidence.data), f"FAIL: Expected .git endpoint to be top priority, got {top_evidence.summary}"
    print("✓ PASS: .git endpoint correctly ranked as highest priority")
    
    # Get knowledge gaps
    gaps = engine.get_knowledge_gaps(model_state)
    print("\nKnowledge Gaps Identified:")
    for gap in gaps[:3]:
        print(f"  - {gap['suggestion']} (priority: {gap['priority']:.2f})")
    
    print("\n" + engine.summary())
    print()
    
    return True


def test_hypothesis_engine():
    """Test the Multi-Hypothesis Reasoning Engine."""
    print("=" * 60)
    print("TEST 2: MULTI-HYPOTHESIS REASONING ENGINE")
    print("=" * 60)
    
    engine = MultiHypothesisEngine()
    
    # Scenario data
    scenario = {
        'ports': [
            {'port': 22, 'service': 'ssh'},
            {'port': 80, 'service': 'http'}
        ],
        'tech_stack': {'nginx': '1.18.0'},
        'endpoints': [
            {'url': '/.git/config', 'method': 'GET', 'status': 200},
            {'url': '/index.html', 'method': 'GET', 'status': 200}
        ]
    }
    
    # Generate competing hypotheses
    hypotheses = engine.generate_from_scenario(scenario)
    
    print(f"\nGenerated {len(hypotheses)} competing hypotheses:")
    print("-" * 60)
    
    for i, hyp in enumerate(hypotheses, 1):
        print(f"{i}. {hyp.summary()}")
        print(f"   Description: {hyp.description}")
        print(f"   Assumptions: {', '.join(hyp.assumptions[:2])}")
        print(f"   Command: {hyp.command[:60]}...")
        print(f"   Scores: conf={hyp.confidence:.2f}, info_gain={hyp.estimated_information_gain:.2f}, "
              f"cost={hyp.estimated_execution_cost:.2f}, risk={hyp.estimated_risk:.2f}")
        print(f"   Priority: {hyp.priority_score:.3f}")
        print()
    
    # Verify multiple hypotheses generated
    assert len(hypotheses) >= 3, f"FAIL: Expected at least 3 hypotheses, got {len(hypotheses)}"
    print(f"✓ PASS: Generated {len(hypotheses)} competing hypotheses (minimum 3 required)")
    
    # Select best hypothesis
    best = engine.select_best_hypothesis()
    if best:
        print(f"\n✓ Selected Best Hypothesis: {best.title}")
        print(f"  Priority Score: {best.priority_score:.3f}")
        print(f"  Command: {best.command}")
        
        # Verify it's the .git hypothesis (should be highest priority due to low cost, high gain)
        assert '.git' in best.title.lower() or 'git' in best.description.lower(), \
            f"FAIL: Expected git-related hypothesis to be selected, got {best.title}"
        print("✓ PASS: Correctly selected git exposure hypothesis as best option")
    
    # Test hypothesis comparison
    if len(hypotheses) >= 2:
        result = engine.compare_hypotheses(hypotheses[0].id, hypotheses[1].id)
        if result:
            print(f"\n✓ Hypothesis Comparison: {result}")
    
    # Test rejection and duplicate prevention
    if hypotheses:
        test_hyp = hypotheses[-1]
        engine.reject_hypothesis(test_hyp.id, "Testing rejection mechanism")
        print(f"\n✓ Rejected hypothesis: {test_hyp.title}")
        print(f"  Reason: {test_hyp.rejection_reason}")
        
        # Try to add similar hypothesis (should be blocked)
        duplicate = engine.add_hypothesis(
            title=test_hyp.title,
            description=test_hyp.description,
            command=test_hyp.command,
            assumptions=test_hyp.assumptions
        )
        assert duplicate is None, "FAIL: Duplicate hypothesis should have been blocked"
        print("✓ PASS: Duplicate hypothesis correctly blocked")
    
    print("\n" + engine.summary())
    print()
    
    # Get learning summary
    learning = engine.get_learning_summary()
    print(f"\nLearning Summary:")
    print(f"  Total: {learning['total_hypotheses']}, Confirmed: {learning['confirmed_count']}, "
          f"Rejected: {learning['rejected_count']}")
    print()
    
    return True


def test_attack_graph():
    """Test the Attack Graph Engine."""
    print("=" * 60)
    print("TEST 3: ATTACK GRAPH ENGINE")
    print("=" * 60)
    
    graph = AttackGraph()
    
    # Build graph from scenario evidence
    evidence_data = {
        'target': '192.168.1.100',
        'ports': [
            {'port': 22, 'service': 'ssh', 'version': 'OpenSSH 8.2', 'proto': 'tcp'},
            {'port': 80, 'service': 'http', 'version': 'nginx 1.18.0', 'proto': 'tcp'}
        ],
        'tech_stack': {'nginx': '1.18.0', 'openssh': '8.2'},
        'endpoints': [
            {'url': '/.git/config', 'method': 'GET', 'status': 200},
            {'url': '/index.html', 'method': 'GET', 'status': 200}
        ],
        'credentials': [
            {'username': 'dev_user', 'service': 'git', 'source': 'found'}
        ],
        'vulnerabilities': []
    }
    
    graph.build_from_evidence(evidence_data)
    
    print("\nAttack Graph Built:")
    print("-" * 60)
    print(graph.summary())
    
    # Verify nodes created
    entry_points = graph.get_entry_points()
    print(f"\n✓ Entry Points: {len(entry_points)}")
    for ep in entry_points:
        print(f"  - {ep.label} (priority: {ep.priority:.2f})")
    
    # Verify .git endpoint has high value
    git_nodes = [n for n in graph._nodes.values() if '.git' in n.label.lower()]
    assert len(git_nodes) > 0, "FAIL: Expected .git node in graph"
    assert git_nodes[0].value_score >= 0.8, f"FAIL: .git node should have high value score, got {git_nodes[0].value_score}"
    print(f"\n✓ PASS: .git endpoint correctly assigned high value ({git_nodes[0].value_score:.2f})")
    
    # Find attack paths
    paths = graph.find_paths(max_length=4)
    print(f"\n✓ Found {len(paths)} attack paths")
    
    if paths:
        print("\nTop Attack Paths:")
        for i, path in enumerate(paths[:3], 1):
            print(f"  {i}. {path.description}")
            print(f"     Value: {path.total_value:.2f}, Difficulty: {path.cumulative_difficulty:.2f}, "
                  f"Success Prob: {path.success_probability:.2f}")
            print(f"     Priority Score: {path.priority_score:.3f}")
    
    # Get optimal next step
    next_step = graph.get_optimal_next_step()
    if next_step:
        node, edge, value_gain = next_step
        print(f"\n✓ Optimal Next Step:")
        print(f"  Target: {node.label}")
        print(f"  Value Gain: {value_gain:.3f}")
        
        # Should prioritize .git or credential
        assert '.git' in node.label.lower() or node.node_type == NODE_CREDENTIAL, \
            f"FAIL: Expected .git or credential as next step, got {node.label}"
        print("✓ PASS: Correctly identified high-value target as next step")
    
    print()
    return True


def test_integrated_scenario():
    """Test integrated cognitive behavior with full scenario."""
    print("=" * 60)
    print("TEST 4: INTEGRATED COGNITIVE SCENARIO")
    print("=" * 60)
    print("\nScenario: Target with SSH(22), HTTP(80), exposed .git, credentials")
    print("-" * 60)
    
    # Initialize all engines
    evidence_engine = EvidenceRankingEngine()
    hypothesis_engine = MultiHypothesisEngine()
    attack_graph = AttackGraph()
    
    # Step 1: Initial reconnaissance results
    print("\n[STEP 1] Processing initial recon results...")
    
    initial_evidence = [
        RankedEvidence(id="e1", source="nmap", kind="port", 
                      data={"port": 22, "service": "ssh"}),
        RankedEvidence(id="e2", source="nmap", kind="port",
                      data={"port": 80, "service": "http"}),
        RankedEvidence(id="e3", source="curl", kind="endpoint",
                      data={"url": "/.git/config", "status": 200}),
    ]
    
    for ev in initial_evidence:
        ev.score.confidence = 0.8
        ev.score.information_gain = evidence_engine.calculate_information_gain(ev, {})
        ev.score.exploitability = evidence_engine.calculate_exploitability(ev)
        ev.score.dependency_value = evidence_engine.calculate_dependency_value(ev)
        ev.score.mission_impact = 0.9 if '.git' in str(ev.data) else 0.5
        ev.score.novelty = 1.0
        ev.score.uncertainty = 0.2
        evidence_engine.add_evidence(ev)
    
    print(f"  Added {len(initial_evidence)} evidence items")
    
    # Step 2: Generate hypotheses
    print("\n[STEP 2] Generating competing hypotheses...")
    
    scenario_data = {
        'ports': [{'port': 22, 'service': 'ssh'}, {'port': 80, 'service': 'http'}],
        'endpoints': [{'url': '/.git/config', 'status': 200}],
        'tech_stack': {}
    }
    
    hypotheses = hypothesis_engine.generate_from_scenario(scenario_data)
    print(f"  Generated {len(hypotheses)} hypotheses")
    
    # Step 3: Build attack graph
    print("\n[STEP 3] Building attack graph...")
    
    evidence_data = {
        'target': 'target.local',
        'ports': [{'port': 22, 'service': 'ssh'}, {'port': 80, 'service': 'http'}],
        'endpoints': [{'url': '/.git/config', 'method': 'GET', 'status': 200}],
        'credentials': []
    }
    
    attack_graph.build_from_evidence(evidence_data)
    print(f"  Graph: {len(attack_graph._nodes)} nodes, {len(attack_graph._edges)} edges")
    
    # Step 4: Cognitive decision making
    print("\n[STEP 4] Cognitive decision making...")
    
    # Get best evidence
    best_evidence = evidence_engine.get_highest_priority_evidence()
    print(f"  Highest Priority Evidence: {best_evidence.summary if best_evidence else 'None'}")
    
    # Get best hypothesis
    best_hypothesis = hypothesis_engine.select_best_hypothesis()
    print(f"  Selected Hypothesis: {best_hypothesis.title if best_hypothesis else 'None'}")
    print(f"    Command: {best_hypothesis.command if best_hypothesis else 'None'}")
    
    # Get optimal attack path step
    next_step = attack_graph.get_optimal_next_step()
    if next_step:
        node, edge, value = next_step
        print(f"  Optimal Next Target: {node.label}")
        print(f"    Expected Value: {value:.3f}")
    
    # Step 5: Verify cognitive behavior
    print("\n[STEP 5] Verifying cognitive behavior...")
    
    checks_passed = 0
    total_checks = 5
    
    # Check 1: Does NOT recommend another nmap scan
    if best_hypothesis and 'nmap' not in best_hypothesis.command.lower():
        print("  ✓ Does NOT recommend redundant nmap scan")
        checks_passed += 1
    else:
        print("  ✗ FAIL: Recommending redundant nmap scan")
    
    # Check 2: Does NOT attempt interactive SSH
    if best_hypothesis and 'ssh' not in best_hypothesis.command.lower() and 'hydra' not in best_hypothesis.command.lower():
        print("  ✓ Does NOT attempt interactive SSH")
        checks_passed += 1
    else:
        print("  ✗ FAIL: Attempting interactive SSH prematurely")
    
    # Check 3: Prioritizes exposed repository
    if best_evidence and '.git' in str(best_evidence.data):
        print("  ✓ Prioritizes exposed .git repository")
        checks_passed += 1
    else:
        print("  ✗ FAIL: Not prioritizing .git exposure")
    
    # Check 4: Multiple hypotheses generated
    if len(hypotheses) >= 3:
        print(f"  ✓ Generated {len(hypotheses)} competing hypotheses")
        checks_passed += 1
    else:
        print(f"  ✗ FAIL: Only {len(hypotheses)} hypotheses generated (need >= 3)")
    
    # Check 5: Attack graph updated
    if len(attack_graph._nodes) >= 3 and len(attack_graph._edges) >= 2:
        print(f"  ✓ Attack graph properly constructed ({len(attack_graph._nodes)} nodes, {len(attack_graph._edges)} edges)")
        checks_passed += 1
    else:
        print(f"  ✗ FAIL: Attack graph underpopulated")
    
    print(f"\n[RESULT] {checks_passed}/{total_checks} cognitive checks passed")
    
    if checks_passed == total_checks:
        print("\n✓✓✓ ALL COGNITIVE BEHAVIOR TESTS PASSED ✓✓✓")
        return True
    else:
        print(f"\n✗✗✗ {total_checks - checks_passed} TESTS FAILED ✗✗✗")
        return False


def main():
    """Run all cognitive verification tests."""
    print("\n" + "=" * 60)
    print("X19 COGNITIVE BRAIN VERIFICATION")
    print("Testing: Evidence Ranking, Multi-Hypothesis, Attack Graph")
    print("=" * 60 + "\n")
    
    results = []
    
    try:
        results.append(("Evidence Ranking", test_evidence_ranking()))
    except Exception as e:
        print(f"✗ Evidence Ranking FAILED: {e}")
        results.append(("Evidence Ranking", False))
    
    try:
        results.append(("Hypothesis Engine", test_hypothesis_engine()))
    except Exception as e:
        print(f"✗ Hypothesis Engine FAILED: {e}")
        results.append(("Hypothesis Engine", False))
    
    try:
        results.append(("Attack Graph", test_attack_graph()))
    except Exception as e:
        print(f"✗ Attack Graph FAILED: {e}")
        results.append(("Attack Graph", False))
    
    try:
        results.append(("Integrated Scenario", test_integrated_scenario()))
    except Exception as e:
        print(f"✗ Integrated Scenario FAILED: {e}")
        results.append(("Integrated Scenario", False))
    
    # Final summary
    print("\n" + "=" * 60)
    print("FINAL VERIFICATION SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 COGNITIVE BRAIN MIGRATION VERIFIED SUCCESSFULLY 🎉")
        print("\nThe system now demonstrates:")
        print("  • Evidence-driven decision making (not first-match)")
        print("  • Multi-hypothesis reasoning (not single-path)")
        print("  • Attack graph path optimization (not linear methodology)")
        print("  • Proper rejection of redundant/weak actions")
        return 0
    else:
        print(f"\n⚠️  {total - passed} COMPONENTS NEED ATTENTION")
        return 1


if __name__ == "__main__":
    sys.exit(main())
