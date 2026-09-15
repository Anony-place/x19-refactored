"""Attack Graph Engine for X19 Cognitive Brain Migration.

Replaces flat findings with a typed graph structure.

Typed Relationships:
  HOST_HAS_SERVICE, SERVICE_SERVES_ENDPOINT, ENDPOINT_HAS_PARAMETER,
  ENDPOINT_EXPOSES, ENDPOINT_VULNERABLE_TO, SERVICE_AFFECTED_BY,
  TECHNOLOGY_AFFECTED_BY, CREDENTIAL_AUTHENTICATES_TO,
  VULNERABILITY_REQUIRES, VULNERABILITY_ENABLES,
  FINDING_CONFIRMS, FINDING_REJECTS, HYPOTHESIS_TESTS,
  EXPERIMENT_PRODUCES_EVIDENCE

Typed Node States:
  UNKNOWN, OBSERVED, IDENTIFIED, CONFIRMED, TESTABLE, VALIDATED,
  EXPLOITABLE, EXPLOITED, REJECTED, STALE, BLOCKED, EXHAUSTED

Every state transition carries provenance/evidence.

Path caching includes: start nodes, end nodes, max depth, graph revision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone
import hashlib
import json


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Node types
# ---------------------------------------------------------------------------
NODE_SERVICE = "service"
NODE_CREDENTIAL = "credential"
NODE_USER = "user"
NODE_TECHNOLOGY = "technology"
NODE_VULNERABILITY = "vulnerability"
NODE_ENDPOINT = "endpoint"
NODE_REPOSITORY = "repository"
NODE_HOST = "host"
NODE_PARAMETER = "parameter"
NODE_FUNDING = "finding"
NODE_HYPOTHESIS = "hypothesis"
NODE_EXPERIMENT = "experiment"
NODE_EVIDENCE = "evidence"

ALL_NODE_TYPES = frozenset({
    NODE_SERVICE, NODE_CREDENTIAL, NODE_USER, NODE_TECHNOLOGY,
    NODE_VULNERABILITY, NODE_ENDPOINT, NODE_REPOSITORY, NODE_HOST,
    NODE_PARAMETER, NODE_FUNDING, NODE_HYPOTHESIS, NODE_EXPERIMENT,
    NODE_EVIDENCE,
})

# ---------------------------------------------------------------------------
# Typed relationship kinds (P0 spec)
# ---------------------------------------------------------------------------
EDGE_HOST_HAS_SERVICE = "HOST_HAS_SERVICE"
EDGE_SERVICE_SERVES_ENDPOINT = "SERVICE_SERVES_ENDPOINT"
EDGE_ENDPOINT_HAS_PARAMETER = "ENDPOINT_HAS_PARAMETER"
EDGE_ENDPOINT_EXPOSES = "ENDPOINT_EXPOSES"
EDGE_ENDPOINT_VULNERABLE_TO = "ENDPOINT_VULNERABLE_TO"
EDGE_SERVICE_AFFECTED_BY = "SERVICE_AFFECTED_BY"
EDGE_TECHNOLOGY_AFFECTED_BY = "TECHNOLOGY_AFFECTED_BY"
EDGE_CREDENTIAL_AUTHENTICATES_TO = "CREDENTIAL_AUTHENTICATES_TO"
EDGE_VULNERABILITY_REQUIRES = "VULNERABILITY_REQUIRES"
EDGE_VULNERABILITY_ENABLES = "VULNERABILITY_ENABLES"
EDGE_FINDING_CONFIRMS = "FINDING_CONFIRMS"
EDGE_FINDING_REJECTS = "FINDING_REJECTS"
EDGE_HYPOTHESIS_TESTS = "HYPOTHESIS_TESTS"
EDGE_EXPERIMENT_PRODUCES_EVIDENCE = "EXPERIMENT_PRODUCES_EVIDENCE"

# Legacy aliases (for backward compat with existing callers)
EDGE_ACCESS = "access"
EDGE_AUTHENTICATES = "authenticates"
EDGE_DEPENDS = "depends_on"
EDGE_EXPLOITS = "exploits"
EDGE_OWNS = "owns"
EDGE_CONTAINS = "contains"
EDGE_RUNS = "runs"
EDGE_VULNERABLE = "vulnerable_to"
EDGE_CONTAINS_LEGACY = "contains"

ALL_EDGE_TYPES = frozenset({
    EDGE_HOST_HAS_SERVICE, EDGE_SERVICE_SERVES_ENDPOINT,
    EDGE_ENDPOINT_HAS_PARAMETER, EDGE_ENDPOINT_EXPOSES,
    EDGE_ENDPOINT_VULNERABLE_TO, EDGE_SERVICE_AFFECTED_BY,
    EDGE_TECHNOLOGY_AFFECTED_BY, EDGE_CREDENTIAL_AUTHENTICATES_TO,
    EDGE_VULNERABILITY_REQUIRES, EDGE_VULNERABILITY_ENABLES,
    EDGE_FINDING_CONFIRMS, EDGE_FINDING_REJECTS,
    EDGE_HYPOTHESIS_TESTS, EDGE_EXPERIMENT_PRODUCES_EVIDENCE,
    # legacy
    EDGE_ACCESS, EDGE_AUTHENTICATES, EDGE_DEPENDS, EDGE_EXPLOITS,
    EDGE_OWNS, EDGE_CONTAINS, EDGE_RUNS, EDGE_VULNERABLE,
})

# ---------------------------------------------------------------------------
# Typed node states (P0 spec)
# ---------------------------------------------------------------------------
NODE_STATE_UNKNOWN = "unknown"
NODE_STATE_OBSERVED = "observed"
NODE_STATE_IDENTIFIED = "identified"
NODE_STATE_CONFIRMED = "confirmed"
NODE_STATE_TESTABLE = "testable"
NODE_STATE_VALIDATED = "validated"
NODE_STATE_EXPLOITABLE = "exploitable"
NODE_STATE_EXPLOITED = "exploited"
NODE_STATE_REJECTED = "rejected"
NODE_STATE_STALE = "stale"
NODE_STATE_BLOCKED = "blocked"
NODE_STATE_EXHAUSTED = "exhausted"

ALL_NODE_STATES = frozenset({
    NODE_STATE_UNKNOWN, NODE_STATE_OBSERVED, NODE_STATE_IDENTIFIED,
    NODE_STATE_CONFIRMED, NODE_STATE_TESTABLE, NODE_STATE_VALIDATED,
    NODE_STATE_EXPLOITABLE, NODE_STATE_EXPLOITED, NODE_STATE_REJECTED,
    NODE_STATE_STALE, NODE_STATE_BLOCKED, NODE_STATE_EXHAUSTED,
})

# Valid transitions (from -> set of allowed to)
VALID_TRANSITIONS: Dict[str, Set[str]] = {
    NODE_STATE_UNKNOWN: {NODE_STATE_OBSERVED, NODE_STATE_REJECTED},
    NODE_STATE_OBSERVED: {NODE_STATE_IDENTIFIED, NODE_STATE_REJECTED, NODE_STATE_STALE},
    NODE_STATE_IDENTIFIED: {NODE_STATE_CONFIRMED, NODE_STATE_TESTABLE, NODE_STATE_REJECTED, NODE_STATE_STALE},
    NODE_STATE_TESTABLE: {NODE_STATE_VALIDATED, NODE_STATE_CONFIRMED, NODE_STATE_REJECTED, NODE_STATE_EXHAUSTED},
    NODE_STATE_CONFIRMED: {NODE_STATE_EXPLOITABLE, NODE_STATE_VALIDATED, NODE_STATE_STALE},
    NODE_STATE_VALIDATED: {NODE_STATE_EXPLOITABLE, NODE_STATE_STALE},
    NODE_STATE_EXPLOITABLE: {NODE_STATE_EXPLOITED, NODE_STATE_BLOCKED, NODE_STATE_STALE},
    NODE_STATE_EXPLOITED: {NODE_STATE_STALE},
    NODE_STATE_REJECTED: {NODE_STATE_UNKNOWN},
    NODE_STATE_STALE: {NODE_STATE_UNKNOWN, NODE_STATE_OBSERVED},
    NODE_STATE_BLOCKED: {NODE_STATE_TESTABLE, NODE_STATE_UNKNOWN},
    NODE_STATE_EXHAUSTED: {NODE_STATE_UNKNOWN},
}


@dataclass
class StateTransition:
    """Provenance for every node state change."""
    from_state: str
    to_state: str
    evidence: str = ""
    timestamp: str = field(default_factory=utc_now)
    source: str = ""


@dataclass
class GraphNode:
    """A node in the attack graph."""
    id: str
    node_type: str
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)
    value_score: float = 0.5
    difficulty_score: float = 0.5
    created_at: str = field(default_factory=utc_now)
    source: str = ""
    # Typed state (P0 spec)
    state: str = NODE_STATE_UNKNOWN
    state_history: List[StateTransition] = field(default_factory=list)

    @property
    def priority(self) -> float:
        return self.value_score * (1.0 - self.difficulty_score)

    def transition(self, new_state: str, evidence: str = "", source: str = "") -> bool:
        """Attempt a state transition. Returns True on success, False if invalid."""
        allowed = VALID_TRANSITIONS.get(self.state, set())
        if new_state not in allowed:
            return False
        transition = StateTransition(
            from_state=self.state,
            to_state=new_state,
            evidence=evidence[:500],
            source=source,
        )
        self.state_history.append(transition)
        self.state = new_state
        return True

    def set_state(self, new_state: str, evidence: str = "", source: str = "") -> None:
        """Force a state (bypasses transition validation for bootstrap/import)."""
        if self.state != new_state:
            transition = StateTransition(
                from_state=self.state,
                to_state=new_state,
                evidence=evidence[:500],
                source=source or "set_state",
            )
            self.state_history.append(transition)
            self.state = new_state

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'type': self.node_type,
            'label': self.label,
            'state': self.state,
            'properties': self.properties,
            'value_score': round(self.value_score, 3),
            'difficulty_score': round(self.difficulty_score, 3),
            'priority': round(self.priority, 3),
            'transitions': len(self.state_history),
        }


@dataclass
class GraphEdge:
    """An edge in the attack graph representing a typed relationship."""
    id: str
    source_node: str
    target_node: str
    edge_type: str
    properties: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.7
    evidence: str = ""
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'source': self.source_node,
            'target': self.target_node,
            'type': self.edge_type,
            'confidence': round(self.confidence, 3),
            'evidence': self.evidence,
            'properties': self.properties,
        }


@dataclass
class AttackPath:
    """A path through the attack graph from entry to target."""
    id: str
    nodes: List[str]
    edges: List[str]
    total_value: float = 0.0
    cumulative_difficulty: float = 0.0
    success_probability: float = 0.0
    description: str = ""
    techniques: List[str] = field(default_factory=list)

    @property
    def priority_score(self) -> float:
        return self.total_value * self.success_probability * (1.0 - self.cumulative_difficulty)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'nodes': self.nodes,
            'edges': self.edges,
            'total_value': round(self.total_value, 3),
            'cumulative_difficulty': round(self.cumulative_difficulty, 3),
            'success_probability': round(self.success_probability, 3),
            'priority_score': round(self.priority_score, 3),
            'description': self.description,
            'techniques': self.techniques,
        }


@dataclass
class PathCacheEntry:
    """Cache key for path queries."""
    start_nodes: Optional[Tuple[str, ...]]
    end_nodes: Optional[Tuple[str, ...]]
    max_depth: int
    graph_revision: int

    def __hash__(self):
        return hash((self.start_nodes, self.end_nodes, self.max_depth, self.graph_revision))


class AttackGraph:
    """Graph-based representation of attack surface and paths.

    The Planner queries this graph to find optimal attack paths based on
    discovered evidence. Revision tracking ensures cache invalidation.
    """

    def __init__(self):
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: Dict[str, GraphEdge] = {}
        self._adjacency: Dict[str, Set[str]] = {}  # node_id -> set of neighbor node_ids
        self._edge_index: Dict[str, Set[str]] = {}  # source_id -> set of edge_ids
        self._revision: int = 0  # incremented on every mutation
        self._paths_cache: Dict[Tuple, List[AttackPath]] = {}
        self._paths_dirty: bool = True

    @property
    def revision(self) -> int:
        return self._revision

    def _generate_id(self, prefix: str, content: str) -> str:
        return f"{prefix}_{hashlib.md5(content.encode()).hexdigest()[:8]}"

    def add_node(
        self,
        node_type: str,
        label: str,
        properties: Optional[Dict[str, Any]] = None,
        value_score: float = 0.5,
        difficulty_score: float = 0.5,
        source: str = "",
        state: str = NODE_STATE_UNKNOWN,
    ) -> GraphNode:
        node_id = self._generate_id(node_type, f"{label}:{str(properties)}")
        if node_id in self._nodes:
            existing = self._nodes[node_id]
            if properties:
                existing.properties.update(properties)
            existing.value_score = max(0.0, min(1.0, value_score))
            existing.difficulty_score = max(0.0, min(1.0, difficulty_score))
            self._revision += 1
            self._paths_dirty = True
            return existing

        node = GraphNode(
            id=node_id,
            node_type=node_type,
            label=label,
            properties=properties or {},
            value_score=max(0.0, min(1.0, value_score)),
            difficulty_score=max(0.0, min(1.0, difficulty_score)),
            source=source,
            state=state,
        )
        self._nodes[node_id] = node
        self._adjacency[node_id] = set()
        self._edge_index[node_id] = set()
        self._revision += 1
        self._paths_dirty = True
        return node

    def add_edge(
        self,
        source_node: str,
        target_node: str,
        edge_type: str,
        properties: Optional[Dict[str, Any]] = None,
        confidence: float = 0.7,
        evidence: str = "",
    ) -> Optional[GraphEdge]:
        if source_node not in self._nodes or target_node not in self._nodes:
            return None
        edge_id = self._generate_id("edge", f"{source_node}->{target_node}:{edge_type}")
        if edge_id in self._edges:
            return self._edges[edge_id]

        edge = GraphEdge(
            id=edge_id,
            source_node=source_node,
            target_node=target_node,
            edge_type=edge_type,
            properties=properties or {},
            confidence=max(0.0, min(1.0, confidence)),
            evidence=evidence[:500],
        )
        self._edges[edge_id] = edge
        self._adjacency[source_node].add(target_node)
        self._edge_index[source_node].add(edge_id)
        self._revision += 1
        self._paths_dirty = True
        return edge

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        return self._nodes.get(node_id)

    def get_neighbors(self, node_id: str, edge_type_filter: Optional[str] = None) -> List[Tuple[GraphNode, GraphEdge]]:
        if node_id not in self._nodes:
            return []
        neighbors = []
        for edge_id in self._edge_index.get(node_id, set()):
            edge = self._edges.get(edge_id)
            if edge and (not edge_type_filter or edge.edge_type == edge_type_filter):
                target = self._nodes.get(edge.target_node)
                if target:
                    neighbors.append((target, edge))
        for other_id, edge_set in self._edge_index.items():
            if other_id == node_id:
                continue
            for edge_id in edge_set:
                edge = self._edges.get(edge_id)
                if edge and edge.target_node == node_id:
                    if not edge_type_filter or edge.edge_type == edge_type_filter:
                        source = self._nodes.get(other_id)
                        if source:
                            neighbors.append((source, edge))
        return neighbors

    def find_paths(
        self,
        start_nodes: Optional[List[str]] = None,
        end_nodes: Optional[List[str]] = None,
        max_length: int = 5,
    ) -> List[AttackPath]:
        """Find attack paths. Cache key includes start/end nodes, depth, and revision."""
        cache_key = (
            tuple(sorted(start_nodes)) if start_nodes else None,
            tuple(sorted(end_nodes)) if end_nodes else None,
            max_length,
            self._revision,
        )
        if cache_key in self._paths_cache:
            return sorted(self._paths_cache[cache_key], key=lambda p: p.priority_score, reverse=True)

        self._recompute_paths(start_nodes, end_nodes, max_length)
        self._paths_cache = {cache_key: self._paths_cache.get(cache_key, [])}
        return sorted(self._paths_cache.get(cache_key, []), key=lambda p: p.priority_score, reverse=True)

    def _recompute_paths(self, start_nodes: Optional[List[str]], end_nodes: Optional[List[str]], max_length: int):
        self._paths_cache.clear()
        if not start_nodes:
            start_nodes = [n.id for n in self._nodes.values() if n.node_type in (NODE_SERVICE, NODE_ENDPOINT)]
        if not end_nodes:
            end_nodes = [
                n.id for n in self._nodes.values()
                if n.node_type in (NODE_CREDENTIAL, NODE_USER) or n.value_score >= 0.8
            ]
        cache_key = (
            tuple(sorted(start_nodes)) if start_nodes else None,
            tuple(sorted(end_nodes)) if end_nodes else None,
            max_length,
            self._revision,
        )
        paths = []
        for start_id in start_nodes:
            self._dfs_paths(start_id, end_nodes, [], [], max_length, set(), paths)
        self._paths_cache[cache_key] = paths
        self._paths_dirty = False

    def _dfs_paths(self, current_id, end_nodes, path_nodes, path_edges, max_length, visited, out):
        if current_id in visited or len(path_nodes) >= max_length:
            return
        visited.add(current_id)
        path_nodes.append(current_id)
        if current_id in end_nodes and len(path_nodes) > 1:
            self._create_path(path_nodes, path_edges, out)
        for neighbor_id in self._adjacency.get(current_id, set()):
            for edge_id in self._edge_index.get(current_id, set()):
                edge = self._edges.get(edge_id)
                if edge and edge.target_node == neighbor_id:
                    new_edges = path_edges + [edge_id]
                    self._dfs_paths(neighbor_id, end_nodes, path_nodes.copy(), new_edges, max_length, visited.copy(), out)
        visited.discard(current_id)

    def _create_path(self, node_ids, edge_ids, out):
        if len(node_ids) < 2 or len(edge_ids) < 1:
            return
        path_id = self._generate_id("path", "->".join(node_ids))
        nodes = [self._nodes[nid] for nid in node_ids if nid in self._nodes]
        edges = [self._edges[eid] for eid in edge_ids if eid in self._edges]
        if not nodes or not edges:
            return
        total_value = sum(n.value_score for n in nodes) / len(nodes)
        cumulative_difficulty = sum(n.difficulty_score for n in nodes) / len(nodes)
        success_prob = sum(e.confidence for e in edges) / len(edges)
        labels = [n.label for n in nodes]
        description = " -> ".join(labels)
        path = AttackPath(
            id=path_id, nodes=node_ids, edges=edge_ids,
            total_value=total_value, cumulative_difficulty=cumulative_difficulty,
            success_probability=success_prob, description=description,
        )
        if not any(p.nodes == path.nodes for p in out):
            out.append(path)

    def get_entry_points(self) -> List[GraphNode]:
        return [n for n in self._nodes.values() if n.node_type in (NODE_SERVICE, NODE_ENDPOINT)]

    def get_high_value_targets(self, min_value: float = 0.7) -> List[GraphNode]:
        return [n for n in self._nodes.values() if n.value_score >= min_value]

    def get_optimal_next_step(self, current_position: Optional[str] = None) -> Optional[Tuple[GraphNode, GraphEdge, float]]:
        paths = self.find_paths(max_length=3)
        if not paths:
            return None
        best_path = paths[0]
        if current_position:
            try:
                idx = best_path.nodes.index(current_position)
                if idx + 1 < len(best_path.nodes):
                    next_node_id = best_path.nodes[idx + 1]
                    next_edge_id = best_path.edges[idx]
                    next_node = self._nodes.get(next_node_id)
                    next_edge = self._edges.get(next_edge_id)
                    if next_node and next_edge:
                        value_gain = next_node.value_score * best_path.success_probability
                        return (next_node, next_edge, value_gain)
            except ValueError:
                pass
        if best_path.nodes:
            first_node = self._nodes.get(best_path.nodes[0])
            first_edge = self._edges.get(best_path.edges[0]) if best_path.edges else None
            if first_node:
                return (first_node, first_edge, first_node.value_score * best_path.success_probability)
        return None

    def build_from_evidence(self, evidence_data: Dict[str, Any]):
        target = evidence_data.get('target', 'unknown')
        host_node = self.add_node(
            NODE_HOST, label=target,
            properties={'hostname': target},
            value_score=1.0, difficulty_score=0.9,
            source='target_definition',
        )
        for port_info in evidence_data.get('ports', []):
            port = port_info.get('port', 0)
            service = port_info.get('service', 'unknown')
            version = port_info.get('version', '')
            service_node = self.add_node(
                NODE_SERVICE, label=f"{service}:{port}",
                properties={'port': port, 'service': service, 'version': version, 'proto': port_info.get('proto', 'tcp')},
                value_score=0.6, difficulty_score=0.4, source='port_scan',
            )
            self.add_edge(host_node.id, service_node.id, EDGE_HOST_HAS_SERVICE, confidence=0.95)
            # Legacy alias
            self.add_edge(host_node.id, service_node.id, EDGE_RUNS, confidence=0.95)
        for tech_name, tech_version in (evidence_data.get('tech_stack', {}) or {}).items():
            tech_node = self.add_node(
                NODE_TECHNOLOGY, label=tech_name,
                properties={'name': tech_name, 'version': tech_version},
                value_score=0.5, difficulty_score=0.3, source='tech_detection',
            )
            for sn in [n for n in self._nodes.values() if n.node_type == NODE_SERVICE]:
                self.add_edge(sn.id, tech_node.id, EDGE_DEPENDS, confidence=0.8)
        for ep in evidence_data.get('endpoints', []):
            url = ep.get('url', '')
            method = ep.get('method', 'GET')
            endpoint_node = self.add_node(
                NODE_ENDPOINT, label=f"{method} {url}",
                properties={'url': url, 'method': method, 'status': ep.get('status', 0)},
                value_score=0.5, difficulty_score=0.3, source='web_enum',
            )
            if any(s in url.lower() for s in ['.git', '.env', 'admin', 'backup', 'config']):
                endpoint_node.value_score = 0.85
                endpoint_node.properties['sensitive'] = True
        for cred in evidence_data.get('credentials', []):
            cred_node = self.add_node(
                NODE_CREDENTIAL, label=cred.get('username', ''),
                properties={'username': cred.get('username', ''), 'service': cred.get('service', '')},
                value_score=0.9,
                difficulty_score=0.2 if cred.get('source') == 'found' else 0.6,
                source=cred.get('source', 'discovered'),
            )
        for vuln in evidence_data.get('vulnerabilities', []):
            title = vuln.get('title', 'Unknown')
            severity = vuln.get('severity', 'info')
            severity_scores = {'critical': 1.0, 'high': 0.85, 'medium': 0.6, 'low': 0.3, 'info': 0.1}
            self.add_node(
                NODE_VULNERABILITY, label=title,
                properties={'title': title, 'severity': severity, 'cve': vuln.get('cve', ''), 'description': vuln.get('description', '')},
                value_score=severity_scores.get(severity, 0.5),
                difficulty_score=0.3, source='vuln_scan',
            )
        self._paths_dirty = True

    def summary(self) -> str:
        lines = ["ATTACK GRAPH SUMMARY:", "=" * 40]
        lines.append(f"Nodes: {len(self._nodes)} | Edges: {len(self._edges)} | Revision: {self._revision}")
        type_counts: Dict[str, int] = {}
        state_counts: Dict[str, int] = {}
        for node in self._nodes.values():
            type_counts[node.node_type] = type_counts.get(node.node_type, 0) + 1
            state_counts[node.state] = state_counts.get(node.state, 0) + 1
        lines.append("\nNodes by type:")
        for t, c in sorted(type_counts.items()):
            lines.append(f"  {t}: {c}")
        lines.append("\nNodes by state:")
        for s, c in sorted(state_counts.items()):
            lines.append(f"  {s}: {c}")
        paths = self.find_paths(max_length=4)
        if paths:
            lines.append("\nTop Attack Paths:")
            for i, path in enumerate(paths[:3], 1):
                lines.append(f"  {i}. {path.description}")
                lines.append(f"     Value: {path.total_value:.2f}, Difficulty: {path.cumulative_difficulty:.2f}, Success: {path.success_probability:.2f}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Dict-shaped read views (used by strategist and coordinator)
    # ------------------------------------------------------------------

    @property
    def nodes(self) -> Dict[str, Dict[str, Any]]:
        view: Dict[str, Dict[str, Any]] = {}
        for node_id, node in self._nodes.items():
            props = node.properties or {}
            view[node_id] = {
                "id": node.id,
                "type": node.node_type,
                "label": node.label,
                "state": node.state,
                "value_score": node.value_score,
                "difficulty_score": node.difficulty_score,
                "priority": node.priority,
                "confidence": props.get("confidence", 0.5),
                "category": props.get("category", node.node_type),
                "technique": props.get("technique", ""),
                "service": props.get("service", ""),
                "port": props.get("port", 0),
                "name": props.get("name", node.label),
                "source": node.source,
                "properties": props,
                "transitions": len(node.state_history),
            }
        return view

    @property
    def edges(self) -> Dict[str, List[Dict[str, Any]]]:
        view: Dict[str, List[Dict[str, Any]]] = {}
        for source_id, edge_ids in self._edge_index.items():
            collected = []
            for edge_id in edge_ids:
                edge = self._edges.get(edge_id)
                if edge is not None:
                    collected.append(edge.to_dict())
            view[source_id] = collected
        return view

    def node_count(self) -> int:
        return len(self._nodes)

    def edge_count(self) -> int:
        return len(self._edges)

    def find_paths_to(self, node_id: str, max_depth: int = 5, limit: int = 64) -> List[List[str]]:
        if not node_id or node_id not in self._nodes:
            return []
        depth = max(1, int(max_depth))
        starts = [n.id for n in self.get_entry_points()] or list(self._nodes.keys())
        found: List[List[str]] = []
        seen = set()
        for start in starts:
            if len(found) >= limit:
                break
            self._collect_paths_to(start, node_id, [start], {start}, found, seen, depth, limit)
        found.sort(key=len)
        return found

    def _collect_paths_to(self, current, target, path, visited, out, seen, max_depth, limit):
        if len(out) >= limit:
            return
        if current == target:
            if len(path) >= 2:
                key = tuple(path)
                if key not in seen:
                    seen.add(key)
                    out.append(list(path))
            return
        if len(path) >= max_depth:
            return
        for neighbor in self._adjacency.get(current, ()):
            if neighbor in visited:
                continue
            visited.add(neighbor)
            path.append(neighbor)
            self._collect_paths_to(neighbor, target, path, visited, out, seen, max_depth, limit)
            path.pop()
            visited.discard(neighbor)
