"""Multi-Hypothesis Reasoning Engine for X19 Cognitive Brain Migration.

Never generate only one hypothesis. Always generate multiple competing hypotheses.
Each hypothesis contains:
- assumptions
- expected_evidence
- confidence
- estimated_information_gain
- estimated_execution_cost
- estimated_risk

The Planner compares hypotheses, chooses the best, rejects weak ones,
and stores rejected hypotheses to never repeat them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone
import math
import hashlib


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# Hypothesis states
HYP_STATE_GENERATED = "GENERATED"
HYP_STATE_SELECTED = "SELECTED"
HYP_STATE_TESTING = "TESTING"
HYP_STATE_CONFIRMED = "CONFIRMED"
HYP_STATE_REJECTED = "REJECTED"
HYP_STATE_SUPERSEDED = "SUPERSEDED"  # Replaced by better hypothesis


@dataclass
class CompetingHypothesis:
    """A testable hypothesis with multi-dimensional scoring."""
    
    id: str
    title: str
    description: str
    
    # Core reasoning components
    assumptions: List[str] = field(default_factory=list)      # What must be true for this to work
    expected_evidence: List[str] = field(default_factory=list)  # What we should find if true
    command: str = ""                                          # Command to test this hypothesis
    command_alternatives: List[str] = field(default_factory=list)  # Backup commands
    
    # Scoring dimensions
    confidence: float = 0.5                                    # How likely is this hypothesis true
    estimated_information_gain: float = 0.5                    # Value of confirming/refuting
    estimated_execution_cost: float = 0.5                      # Time/resources required (0=cheap, 1=expensive)
    estimated_risk: float = 0.3                                # Risk of detection/disruption (0=safe, 1=risky)
    
    # Dependencies and relationships
    depends_on: List[str] = field(default_factory=list)        # IDs of other hypotheses this requires
    contradicts: List[str] = field(default_factory=list)       # IDs of incompatible hypotheses
    supports: List[str] = field(default_factory=list)          # IDs of hypotheses this strengthens
    
    # State tracking
    state: str = HYP_STATE_GENERATED
    generation_reason: str = ""                                # Why was this hypothesis generated
    tested_count: int = 0                                      # How many times tested
    last_tested: Optional[str] = None                          # Timestamp of last test
    confirmation_evidence: List[str] = field(default_factory=list)  # Evidence that supports this
    rejection_reason: Optional[str] = None                     # Why it was rejected
    
    # Metadata
    created_at: str = field(default_factory=utc_now)
    source: str = "llm"                                        # llm, engine, template, etc.
    tags: List[str] = field(default_factory=list)              # For categorization
    
    @property
    def priority_score(self) -> float:
        """Calculate priority score for hypothesis selection.
        
        Favors high-confidence, high-information-gain, low-cost, low-risk hypotheses.
        """
        # Weighted combination
        weights = {
            'confidence': 0.25,
            'information_gain': 0.35,
            'cost': 0.20,      # Inverted: lower cost = higher priority
            'risk': 0.20,      # Inverted: lower risk = higher priority
        }
        
        score = (
            weights['confidence'] * self.confidence +
            weights['information_gain'] * self.estimated_information_gain +
            weights['cost'] * (1.0 - self.estimated_execution_cost) +
            weights['risk'] * (1.0 - self.estimated_risk)
        )
        
        # Penalty for already-tested hypotheses (avoid repetition)
        if self.tested_count > 0:
            score *= (0.8 ** self.tested_count)
        
        # Penalty for rejected hypotheses
        if self.state == HYP_STATE_REJECTED:
            score *= 0.1
        
        return max(0.0, min(1.0, score))
    
    @property
    def is_active(self) -> bool:
        """Check if hypothesis is still viable for testing."""
        return self.state in (HYP_STATE_GENERATED, HYP_STATE_SELECTED, HYP_STATE_TESTING)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'assumptions': self.assumptions,
            'expected_evidence': self.expected_evidence,
            'command': self.command,
            'command_alternatives': self.command_alternatives,
            'confidence': round(self.confidence, 3),
            'estimated_information_gain': round(self.estimated_information_gain, 3),
            'estimated_execution_cost': round(self.estimated_execution_cost, 3),
            'estimated_risk': round(self.estimated_risk, 3),
            'priority_score': round(self.priority_score, 3),
            'state': self.state,
            'tested_count': self.tested_count,
            'tags': self.tags,
        }
    
    def summary(self) -> str:
        """Human-readable summary."""
        status_icon = {
            HYP_STATE_GENERATED: "💡",
            HYP_STATE_SELECTED: "🎯",
            HYP_STATE_TESTING: "🔬",
            HYP_STATE_CONFIRMED: "✅",
            HYP_STATE_REJECTED: "❌",
            HYP_STATE_SUPERSEDED: "➡️",
        }.get(self.state, "❓")
        
        return f"{status_icon} [{self.state}] {self.title} (priority={self.priority_score:.2f})"


class HypothesisComparisonResult:
    """Result of comparing two hypotheses."""
    
    def __init__(self, winner: CompetingHypothesis, loser: CompetingHypothesis, 
                 reason: str, margin: float):
        self.winner = winner
        self.loser = loser
        self.reason = reason
        self.margin = margin  # Difference in priority scores
    
    def __str__(self) -> str:
        return f"{self.winner.title} > {self.loser.title} by {self.margin:.2f} ({self.reason})"


class MultiHypothesisEngine:
    """Manages generation, comparison, and selection of competing hypotheses.
    
    Ensures multiple hypotheses are always considered, weak ones are rejected,
    and rejected hypotheses are never repeated.
    """
    
    def __init__(self):
        self._hypotheses: Dict[str, CompetingHypothesis] = {}
        self._rejected_hashes: Set[str] = set()  # Hashes of rejected hypotheses to prevent repeats
        self._comparison_history: List[HypothesisComparisonResult] = []
        self._generation_context: Dict[str, Any] = {}  # Context used for generation
        
    def generate_hypothesis_id(self, title: str, command: str, assumptions: List[str]) -> str:
        """Generate unique ID for a hypothesis."""
        content = f"{title}:{command}:{','.join(sorted(assumptions))}"
        return hashlib.md5(content.encode()).hexdigest()[:12]
    
    def _hash_hypothesis(self, title: str, command: str, assumptions: List[str]) -> str:
        """Create hash for duplicate detection."""
        content = f"{title}:{command}:{','.join(sorted(assumptions))}"
        return hashlib.sha256(content.encode()).hexdigest()
    
    def is_duplicate_or_rejected(self, title: str, command: str, assumptions: List[str]) -> bool:
        """Check if this hypothesis (or very similar one) was already rejected."""
        h = self._hash_hypothesis(title, command, assumptions)
        return h in self._rejected_hashes
    
    def add_hypothesis(
        self,
        title: str,
        description: str,
        command: str,
        assumptions: Optional[List[str]] = None,
        expected_evidence: Optional[List[str]] = None,
        confidence: float = 0.5,
        information_gain: float = 0.5,
        execution_cost: float = 0.5,
        risk: float = 0.3,
        depends_on: Optional[List[str]] = None,
        contradicts: Optional[List[str]] = None,
        supports: Optional[List[str]] = None,
        generation_reason: str = "",
        tags: Optional[List[str]] = None,
        command_alternatives: Optional[List[str]] = None,
    ) -> CompetingHypothesis:
        """Add a new hypothesis to the engine.
        
        Returns the created hypothesis, or None if duplicate/rejected.
        """
        assumptions = assumptions or []
        
        # Check for duplicates/rejects
        if self.is_duplicate_or_rejected(title, command, assumptions):
            return None
        
        hyp_id = self.generate_hypothesis_id(title, command, assumptions)
        
        # Check if ID already exists
        if hyp_id in self._hypotheses:
            return self._hypotheses[hyp_id]
        
        hyp = CompetingHypothesis(
            id=hyp_id,
            title=title,
            description=description,
            assumptions=assumptions,
            expected_evidence=expected_evidence or [],
            command=command,
            command_alternatives=command_alternatives or [],
            confidence=max(0.0, min(1.0, confidence)),
            estimated_information_gain=max(0.0, min(1.0, information_gain)),
            estimated_execution_cost=max(0.0, min(1.0, execution_cost)),
            estimated_risk=max(0.0, min(1.0, risk)),
            depends_on=depends_on or [],
            contradicts=contradicts or [],
            supports=supports or [],
            generation_reason=generation_reason,
            tags=tags or [],
        )
        
        self._hypotheses[hyp_id] = hyp
        return hyp
    
    def get_competing_hypotheses(self, limit: int = 5, active_only: bool = True) -> List[CompetingHypothesis]:
        """Return top competing hypotheses sorted by priority.
        
        Args:
            limit: Maximum number to return
            active_only: If True, only return non-rejected hypotheses
        
        Returns:
            List of hypotheses sorted by priority_score descending
        """
        candidates = list(self._hypotheses.values())
        
        if active_only:
            candidates = [h for h in candidates if h.is_active]
        
        # Sort by priority score
        candidates.sort(key=lambda h: h.priority_score, reverse=True)
        
        return candidates[:limit]
    
    def select_best_hypothesis(self) -> Optional[CompetingHypothesis]:
        """Select the single best hypothesis for testing."""
        top = self.get_competing_hypotheses(limit=1, active_only=True)
        if top:
            top[0].state = HYP_STATE_SELECTED
            return top[0]
        return None
    
    def compare_hypotheses(self, hyp1_id: str, hyp2_id: str) -> Optional[HypothesisComparisonResult]:
        """Compare two hypotheses and determine which is better."""
        hyp1 = self._hypotheses.get(hyp1_id)
        hyp2 = self._hypotheses.get(hyp2_id)
        
        if not hyp1 or not hyp2:
            return None
        
        diff = hyp1.priority_score - hyp2.priority_score
        
        if abs(diff) < 0.05:
            reason = "marginal difference - both worth considering"
        elif hyp1.confidence > hyp2.confidence:
            reason = "higher confidence"
        elif hyp1.estimated_information_gain > hyp2.estimated_information_gain:
            reason = "higher information gain"
        elif hyp1.estimated_execution_cost < hyp2.estimated_execution_cost:
            reason = "lower execution cost"
        elif hyp1.estimated_risk < hyp2.estimated_risk:
            reason = "lower risk"
        else:
            reason = "combined scoring factors"
        
        if diff >= 0:
            result = HypothesisComparisonResult(hyp1, hyp2, reason, abs(diff))
        else:
            result = HypothesisComparisonResult(hyp2, hyp1, reason, abs(diff))
        
        self._comparison_history.append(result)
        return result
    
    def reject_hypothesis(self, hyp_id: str, reason: str):
        """Reject a hypothesis and record why."""
        hyp = self._hypotheses.get(hyp_id)
        if not hyp:
            return
        
        hyp.state = HYP_STATE_REJECTED
        hyp.rejection_reason = reason
        hyp.tested_count += 1
        hyp.last_tested = utc_now()
        
        # Add to rejected hashes to prevent similar hypotheses
        h = self._hash_hypothesis(hyp.title, hyp.command, hyp.assumptions)
        self._rejected_hashes.add(h)
        
        # Mark contradictory hypotheses as more confident
        for contra_id in hyp.contradicts:
            if contra_id in self._hypotheses:
                self._hypotheses[contra_id].confidence = min(1.0, self._hypotheses[contra_id].confidence + 0.15)
    
    def confirm_hypothesis(self, hyp_id: str, evidence: List[str]):
        """Confirm a hypothesis with supporting evidence."""
        hyp = self._hypotheses.get(hyp_id)
        if not hyp:
            return
        
        hyp.state = HYP_STATE_CONFIRMED
        hyp.confirmation_evidence = evidence
        hyp.tested_count += 1
        hyp.last_tested = utc_now()
        
        # Mark supported hypotheses as more confident
        for support_id in hyp.supports:
            if support_id in self._hypotheses:
                self._hypotheses[support_id].confidence = min(1.0, self._hypotheses[support_id].confidence + 0.2)
        
        # Mark contradictory hypotheses as rejected
        for contra_id in hyp.contradicts:
            if contra_id in self._hypotheses:
                self.reject_hypothesis(contra_id, f"Contradicted by confirmed hypothesis: {hyp.title}")
    
    def mark_testing(self, hyp_id: str):
        """Mark a hypothesis as currently being tested."""
        hyp = self._hypotheses.get(hyp_id)
        if hyp:
            hyp.state = HYP_STATE_TESTING
            hyp.tested_count += 1
            hyp.last_tested = utc_now()
    
    def supersede_hypothesis(self, old_hyp_id: str, new_hyp_id: str):
        """Mark an old hypothesis as superseded by a new one."""
        old_hyp = self._hypotheses.get(old_hyp_id)
        new_hyp = self._hypotheses.get(new_hyp_id)
        
        if old_hyp and new_hyp:
            old_hyp.state = HYP_STATE_SUPERSEDED
            old_hyp.rejection_reason = f"Superseded by better hypothesis: {new_hyp.title}"
            new_hyp.depends_on.append(old_hyp_id)
    
    def get_hypothesis_chain(self, hyp_id: str) -> List[CompetingHypothesis]:
        """Get the chain of dependencies for a hypothesis."""
        chain = []
        visited = set()
        
        def traverse(current_id: str):
            if current_id in visited or current_id not in self._hypotheses:
                return
            visited.add(current_id)
            hyp = self._hypotheses[current_id]
            chain.append(hyp)
            for dep_id in hyp.depends_on:
                traverse(dep_id)
        
        traverse(hyp_id)
        return list(reversed(chain))  # Return from root to leaf
    
    def get_confirmed_hypotheses(self) -> List[CompetingHypothesis]:
        """Return all confirmed hypotheses."""
        return [h for h in self._hypotheses.values() if h.state == HYP_STATE_CONFIRMED]
    
    def get_rejected_hypotheses(self) -> List[CompetingHypothesis]:
        """Return all rejected hypotheses (for learning)."""
        return [h for h in self._hypotheses.values() if h.state == HYP_STATE_REJECTED]
    
    def get_learning_summary(self) -> Dict[str, Any]:
        """Generate summary for cognitive memory/learning."""
        confirmed = self.get_confirmed_hypotheses()
        rejected = self.get_rejected_hypotheses()
        
        return {
            'total_hypotheses': len(self._hypotheses),
            'confirmed_count': len(confirmed),
            'rejected_count': len(rejected),
            'active_count': len([h for h in self._hypotheses.values() if h.is_active]),
            'confirmed_patterns': [
                {
                    'title': h.title,
                    'assumptions': h.assumptions,
                    'evidence': h.confirmation_evidence,
                }
                for h in confirmed
            ],
            'rejected_patterns': [
                {
                    'title': h.title,
                    'reason': h.rejection_reason,
                    'failed_assumptions': h.assumptions,
                }
                for h in rejected
            ],
            'comparison_insights': [
                str(c) for c in self._comparison_history[-10:]  # Last 10 comparisons
            ]
        }
    
    def generate_from_scenario(self, scenario_data: Dict[str, Any]) -> List[CompetingHypothesis]:
        """Generate competing hypotheses from a target scenario.
        
        This is a template-based generator for when LLM is unavailable.
        In production, LLM should generate hypotheses based on World Model.
        
        Args:
            scenario_data: Dict containing ports, services, technologies, etc.
        
        Returns:
            List of generated hypotheses
        """
        hypotheses = []
        
        ports = scenario_data.get('ports', [])
        tech_stack = scenario_data.get('tech_stack', {})
        endpoints = scenario_data.get('endpoints', [])
        
        # Generate hypotheses based on common attack patterns
        
        # Web-related hypotheses
        web_ports = [p for p in ports if p.get('port') in {80, 443, 8080, 8443}]
        if web_ports:
            # Hypothesis: Directory enumeration will find sensitive paths
            h1 = self.add_hypothesis(
                title="Directory Enumeration Discovery",
                description="Web directory brute-forcing will discover hidden/sensitive paths",
                command="gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt",
                assumptions=["Web server is responding", "Standard wordlist covers common paths"],
                expected_evidence=["HTTP 200/301 responses for discovered paths", "Interesting directories like /admin, /backup"],
                confidence=0.7,
                information_gain=0.8,
                execution_cost=0.4,
                risk=0.2,
                generation_reason="Web port detected",
                tags=["web", "enumeration"],
                command_alternatives=[
                    "ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt",
                    "dirsearch -u http://target -e php,html,js"
                ]
            )
            if h1:
                hypotheses.append(h1)
            
            # Hypothesis: Technology-specific vulnerabilities exist
            for tech_name in tech_stack.keys():
                if tech_name.lower() in ['wordpress', 'joomla', 'drupal']:
                    h2 = self.add_hypothesis(
                        title=f"{tech_name} Plugin Vulnerability",
                        description=f"The {tech_name} installation has vulnerable plugins/themes",
                        command=f"wpscan --url http://target --enumerate vp,vt,u" if tech_name.lower() == 'wordpress' else f"nuclei -t /nuclei-templates/{tech_name.lower()}/",
                        assumptions=[f"{tech_name} is installed and detectable", "Public CVEs exist for plugins/themes"],
                        expected_evidence=["CVE matches", "Version disclosure", "Plugin listings"],
                        confidence=0.5,
                        information_gain=0.85,
                        execution_cost=0.5,
                        risk=0.3,
                        generation_reason=f"{tech_name} technology detected",
                        tags=["web", "cms", "vulnerability"]
                    )
                    if h2:
                        hypotheses.append(h2)
        
        # Git exposure hypothesis
        git_endpoints = [e for e in endpoints if '.git' in e.get('url', '').lower()]
        if git_endpoints or any('.git' in str(t).lower() for t in tech_stack.keys()):
            h3 = self.add_hypothesis(
                title="Git Repository Exposure",
                description=".git directory is publicly accessible, may contain sensitive history",
                command="curl -sik http://target/.git/config",
                assumptions=[".git directory exists", "Web server allows access to .git"],
                expected_evidence=["Git config file content", "Repository structure disclosure"],
                confidence=0.6,
                information_gain=0.9,
                execution_cost=0.1,
                risk=0.1,
                generation_reason=".git endpoint detected or suspected",
                tags=["exposure", "source-code", "credentials"],
                command_alternatives=[
                    "git-dumper http://target/.git ./dump",
                    "curl -sik http://target/.git/HEAD"
                ]
            )
            if h3:
                hypotheses.append(h3)
        
        # Credential discovery from git hypothesis
        if git_endpoints:
            h4 = self.add_hypothesis(
                title="Credentials in Git History",
                description="Git commit history contains hardcoded credentials or secrets",
                command="curl -sik http://target/.git/logs/HEAD",
                assumptions=[".git is accessible", "Commits contain sensitive data"],
                expected_evidence=["Commit messages", "Potential credential strings", "Developer emails"],
                confidence=0.5,
                information_gain=0.95,
                execution_cost=0.2,
                risk=0.1,
                generation_reason=".git exposure confirmed",
                tags=["credentials", "source-code"],
                depends_on=[h3.id] if h3 else [],
                command_alternatives=[
                    "curl -sik http://target/.git/index",
                ]
            )
            if h4:
                hypotheses.append(h4)
                if h3:
                    h3.supports.append(h4.id)
        
        # SSH hypothesis
        ssh_ports = [p for p in ports if p.get('port') == 22]
        if ssh_ports:
            h5 = self.add_hypothesis(
                title="SSH Weak Authentication",
                description="SSH service accepts weak/default credentials or has misconfigurations",
                command="nmap -p 22 --script ssh-auth-methods,ssh-brute target",
                assumptions=["SSH service is OpenSSH or compatible", "Default credentials may exist"],
                expected_evidence=["Authentication method disclosure", "Valid credentials if brute succeeds"],
                confidence=0.4,
                information_gain=0.7,
                execution_cost=0.6,
                risk=0.4,
                generation_reason="SSH port detected",
                tags=["ssh", "authentication"],
                command_alternatives=[
                    "hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://target",
                ]
            )
            if h5:
                hypotheses.append(h5)
        
        self._generation_context = scenario_data
        return hypotheses
    
    def summary(self) -> str:
        """Generate human-readable summary of hypothesis state."""
        lines = ["MULTI-HYPOTHESIS ENGINE STATE:", "=" * 40]
        
        total = len(self._hypotheses)
        confirmed = len(self.get_confirmed_hypotheses())
        rejected = len(self.get_rejected_hypotheses())
        active = total - confirmed - rejected
        
        lines.append(f"Total: {total} | Active: {active} | Confirmed: {confirmed} | Rejected: {rejected}")
        
        # Top active hypotheses
        top_active = self.get_competing_hypotheses(limit=5)
        if top_active:
            lines.append("\nTop Active Hypotheses:")
            for i, h in enumerate(top_active, 1):
                lines.append(f"  {i}. {h.summary()}")
                if h.assumptions:
                    lines.append(f"     Assumes: {', '.join(h.assumptions[:2])}")
        
        # Recent rejections (for learning)
        recent_rejected = self.get_rejected_hypotheses()[-3:]
        if recent_rejected:
            lines.append("\nRecently Rejected (do not repeat):")
            for h in recent_rejected:
                lines.append(f"  ❌ {h.title}: {h.rejection_reason}")
        
        return "\n".join(lines)
