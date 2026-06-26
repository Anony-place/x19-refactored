"""Attack Graph Engine for X19 Cognitive Brain Migration.

Replaces flat findings with a graph structure:

Nodes:
- services
- credentials
- repositories
- users
- technologies
- vulnerabilities

Edges:
- trust
- authentication
- dependency
- network access
- version relation
- credential reuse

The Planner chooses the highest-value path through the graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone
import hashlib


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# Node types
NODE_SERVICE = "service"
NODE_CREDENTIAL = "credential"
NODE_USER = "user"
NODE_TECHNOLOGY = "technology"
NODE_VULNERABILITY = "vulnerability"
NODE_ENDPOINT = "endpoint"
NODE_REPOSITORY = "repository"
NODE_HOST = "host"

# Edge types
EDGE_ACCESS = "access"           # Can reach/access
EDGE_AUTHENTICATES = "authenticates"  # Credential authenticates to
EDGE_DEPENDS = "depends_on"      # Technology depends on another
EDGE_EXPLOITS = "exploits"       # Vulnerability exploits service/tech
EDGE_OWNS = "owns"               # User owns credential
EDGE_CONTAINS = "contains"       # Repository contains credentials
EDGE_RUNS = "runs"               # Host runs service
EDGE_VULNERABLE = "vulnerable_to"  # Service/tech is vulnerable to


@dataclass
class GraphNode:
    """A node in the attack graph."""
    
    id: str
    node_type: str
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)
    
    # Scoring
    value_score: float = 0.5       # How valuable is this node to compromise
    difficulty_score: float = 0.5  # How hard is it to reach/exploit
    
    # Metadata
    created_at: str = field(default_factory=utc_now)
    source: str = ""               # Evidence source
    
    @property
    def priority(self) -> float:
        """Priority for targeting (high value, low difficulty)."""
        return self.value_score * (1.0 - self.difficulty_score)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'type': self.node_type,
            'label': self.label,
            'properties': self.properties,
            'value_score': round(self.value_score, 3),
            'difficulty_score': round(self.difficulty_score, 3),
            'priority': round(self.priority, 3),
        }


@dataclass
class GraphEdge:
    """An edge in the attack graph representing a relationship."""
    
    id: str
    source_node: str        # Source node ID
    target_node: str        # Target node ID
    edge_type: str
    properties: Dict[str, Any] = field(default_factory=dict)
    
    # Confidence in this relationship
    confidence: float = 0.7
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'source': self.source_node,
            'target': self.target_node,
            'type': self.edge_type,
            'confidence': round(self.confidence, 3),
            'properties': self.properties,
        }


@dataclass
class AttackPath:
    """A path through the attack graph from entry to target."""
    
    id: str
    nodes: List[str]          # Ordered list of node IDs
    edges: List[str]          # Ordered list of edge IDs
    
    # Path scoring
    total_value: float = 0.0   # Sum of node values
    cumulative_difficulty: float = 0.0  # Combined difficulty
    success_probability: float = 0.0     # Estimated probability of success
    
    # Metadata
    description: str = ""
    techniques: List[str] = field(default_factory=list)  # MITRE ATT&CK or similar
    
    @property
    def priority_score(self) -> float:
        """Priority score for path selection."""
        # High value, low difficulty, high success probability
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


class AttackGraph:
    """Graph-based representation of attack surface and paths.
    
    The Planner queries this graph to find optimal attack paths
    based on discovered evidence.
    """
    
    def __init__(self):
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: Dict[str, GraphEdge] = {}
        self._adjacency: Dict[str, Set[str]] = {}  # node_id -> set of neighbor node_ids
        self._edge_index: Dict[str, Set[str]] = {}  # source_id -> set of edge_ids
        
        self._paths_cache: List[AttackPath] = []
        self._paths_dirty: bool = True
    
    def _generate_id(self, prefix: str, content: str) -> str:
        """Generate unique ID for node or edge."""
        return f"{prefix}_{hashlib.md5(content.encode()).hexdigest()[:8]}"
    
    def add_node(
        self,
        node_type: str,
        label: str,
        properties: Optional[Dict[str, Any]] = None,
        value_score: float = 0.5,
        difficulty_score: float = 0.5,
        source: str = "",
    ) -> GraphNode:
        """Add a node to the attack graph."""
        node_id = self._generate_id(node_type, f"{label}:{str(properties)}")
        
        if node_id in self._nodes:
            # Update existing node
            existing = self._nodes[node_id]
            if properties:
                existing.properties.update(properties)
            existing.value_score = max(0.0, min(1.0, value_score))
            existing.difficulty_score = max(0.0, min(1.0, difficulty_score))
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
        )
        
        self._nodes[node_id] = node
        self._adjacency[node_id] = set()
        self._edge_index[node_id] = set()
        self._paths_dirty = True
        
        return node
    
    def add_edge(
        self,
        source_node: str,
        target_node: str,
        edge_type: str,
        properties: Optional[Dict[str, Any]] = None,
        confidence: float = 0.7,
    ) -> Optional[GraphEdge]:
        """Add an edge between two nodes."""
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
        )
        
        self._edges[edge_id] = edge
        self._adjacency[source_node].add(target_node)
        self._edge_index[source_node].add(edge_id)
        self._paths_dirty = True
        
        return edge
    
    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Get a node by ID."""
        return self._nodes.get(node_id)
    
    def get_neighbors(self, node_id: str, edge_type_filter: Optional[str] = None) -> List[Tuple[GraphNode, GraphEdge]]:
        """Get neighboring nodes with connecting edges."""
        if node_id not in self._nodes:
            return []
        
        neighbors = []
        for edge_id in self._edge_index.get(node_id, set()):
            edge = self._edges.get(edge_id)
            if edge and (not edge_type_filter or edge.edge_type == edge_type_filter):
                target = self._nodes.get(edge.target_node)
                if target:
                    neighbors.append((target, edge))
        
        # Also check reverse edges
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
        """Find attack paths through the graph.
        
        Args:
            start_nodes: Optional filter for starting nodes (e.g., entry points)
            end_nodes: Optional filter for ending nodes (e.g., high-value targets)
            max_length: Maximum path length
        
        Returns:
            List of AttackPath sorted by priority_score
        """
        if self._paths_dirty or not self._paths_cache:
            self._recompute_paths(start_nodes, end_nodes, max_length)
        
        return sorted(self._paths_cache, key=lambda p: p.priority_score, reverse=True)
    
    def _recompute_paths(self, start_nodes: Optional[List[str]], end_nodes: Optional[List[str]], max_length: int):
        """Recompute all attack paths (called when graph changes)."""
        self._paths_cache = []
        
        # If no start nodes specified, use entry points (services, endpoints)
        if not start_nodes:
            start_nodes = [
                n.id for n in self._nodes.values()
                if n.node_type in (NODE_SERVICE, NODE_ENDPOINT)
            ]
        
        # If no end nodes specified, use high-value targets
        if not end_nodes:
            end_nodes = [
                n.id for n in self._nodes.values()
                if n.node_type in (NODE_CREDENTIAL, NODE_USER) or n.value_score >= 0.8
            ]
        
        # DFS to find paths
        for start_id in start_nodes:
            self._dfs_paths(start_id, end_nodes, [], [], max_length, set())
        
        self._paths_dirty = False
    
    def _dfs_paths(
        self,
        current_id: str,
        end_nodes: List[str],
        path_nodes: List[str],
        path_edges: List[str],
        max_length: int,
        visited: Set[str],
    ):
        """Depth-first search for paths."""
        if current_id in visited or len(path_nodes) >= max_length:
            return
        
        visited.add(current_id)
        path_nodes.append(current_id)
        
        # Check if we reached an end node
        if current_id in end_nodes and len(path_nodes) > 1:
            self._create_path(path_nodes, path_edges)
        
        # Continue DFS
        for neighbor_id in self._adjacency.get(current_id, set()):
            # Find edge between current and neighbor
            for edge_id in self._edge_index.get(current_id, set()):
                edge = self._edges.get(edge_id)
                if edge and edge.target_node == neighbor_id:
                    new_edges = path_edges + [edge_id]
                    self._dfs_paths(neighbor_id, end_nodes, path_nodes.copy(), new_edges, max_length, visited.copy())
        
        visited.discard(current_id)
    
    def _create_path(self, node_ids: List[str], edge_ids: List[str]):
        """Create an AttackPath from node and edge lists."""
        if len(node_ids) < 2 or len(edge_ids) < 1:
            return
        
        path_id = self._generate_id("path", "->".join(node_ids))
        
        # Calculate path scores
        nodes = [self._nodes[nid] for nid in node_ids if nid in self._nodes]
        edges = [self._edges[eid] for eid in edge_ids if eid in self._edges]
        
        if not nodes or not edges:
            return
        
        total_value = sum(n.value_score for n in nodes) / len(nodes)
        cumulative_difficulty = sum(n.difficulty_score for n in nodes) / len(nodes)
        success_prob = sum(e.confidence for e in edges) / len(edges)
        
        # Generate description
        labels = [n.label for n in nodes]
        description = " -> ".join(labels)
        
        path = AttackPath(
            id=path_id,
            nodes=node_ids,
            edges=edge_ids,
            total_value=total_value,
            cumulative_difficulty=cumulative_difficulty,
            success_probability=success_prob,
            description=description,
        )
        
        # Avoid duplicate paths
        if not any(p.nodes == path.nodes for p in self._paths_cache):
            self._paths_cache.append(path)
    
    def get_entry_points(self) -> List[GraphNode]:
        """Return nodes that are potential entry points."""
        return [
            n for n in self._nodes.values()
            if n.node_type in (NODE_SERVICE, NODE_ENDPOINT)
        ]
    
    def get_high_value_targets(self, min_value: float = 0.7) -> List[GraphNode]:
        """Return high-value target nodes."""
        return [
            n for n in self._nodes.values()
            if n.value_score >= min_value
        ]
    
    def get_optimal_next_step(self, current_position: Optional[str] = None) -> Optional[Tuple[GraphNode, GraphEdge, float]]:
        """Get the optimal next step from current position.
        
        Returns:
            Tuple of (target_node, connecting_edge, expected_value_gain) or None
        """
        paths = self.find_paths(max_length=3)
        
        if not paths:
            return None
        
        best_path = paths[0]
        
        # If we have a current position, find the next node in the best path
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
        
        # Otherwise, return the first step of the best path
        if best_path.nodes:
            first_node = self._nodes.get(best_path.nodes[0])
            first_edge = self._edges.get(best_path.edges[0]) if best_path.edges else None
            
            if first_node:
                return (first_node, first_edge, first_node.value_score * best_path.success_probability)
        
        return None
    
    def build_from_evidence(self, evidence_data: Dict[str, Any]):
        """Build attack graph from collected evidence.
        
        This populates the graph based on discovered ports, services,
        credentials, vulnerabilities, etc.
        """
        # Add host node
        target = evidence_data.get('target', 'unknown')
        host_node = self.add_node(
            NODE_HOST,
            label=target,
            properties={'hostname': target},
            value_score=1.0,
            difficulty_score=0.9,
            source='target_definition'
        )
        
        # Add service nodes
        for port_info in evidence_data.get('ports', []):
            port = port_info.get('port', 0)
            service = port_info.get('service', 'unknown')
            version = port_info.get('version', '')
            
            service_node = self.add_node(
                NODE_SERVICE,
                label=f"{service}:{port}",
                properties={
                    'port': port,
                    'service': service,
                    'version': version,
                    'proto': port_info.get('proto', 'tcp'),
                },
                value_score=0.6,
                difficulty_score=0.4,
                source='port_scan'
            )
            
            # Connect host to service
            self.add_edge(host_node.id, service_node.id, EDGE_RUNS, confidence=0.95)
            
            # Add technology nodes if detected
            tech_stack = evidence_data.get('tech_stack', {})
            for tech_name, tech_version in tech_stack.items():
                tech_node = self.add_node(
                    NODE_TECHNOLOGY,
                    label=tech_name,
                    properties={'name': tech_name, 'version': tech_version},
                    value_score=0.5,
                    difficulty_score=0.3,
                    source='tech_detection'
                )
                
                # Connect service to technology
                self.add_edge(service_node.id, tech_node.id, EDGE_DEPENDS, confidence=0.8)
        
        # Add endpoint nodes
        for ep in evidence_data.get('endpoints', []):
            url = ep.get('url', '')
            method = ep.get('method', 'GET')
            
            endpoint_node = self.add_node(
                NODE_ENDPOINT,
                label=f"{method} {url}",
                properties={'url': url, 'method': method, 'status': ep.get('status', 0)},
                value_score=0.5,
                difficulty_score=0.3,
                source='web_enum'
            )
            
            # Check for sensitive endpoints
            if any(s in url.lower() for s in ['.git', '.env', 'admin', 'backup', 'config']):
                endpoint_node.value_score = 0.85
                endpoint_node.properties['sensitive'] = True
        
        # Add credential nodes
        for cred in evidence_data.get('credentials', []):
            username = cred.get('username', '')
            service = cred.get('service', '')
            
            cred_node = self.add_node(
                NODE_CREDENTIAL,
                label=username,
                properties={'username': username, 'service': service},
                value_score=0.9,
                difficulty_score=0.2 if cred.get('source') == 'found' else 0.6,
                source=cred.get('source', 'discovered')
            )
        
        # Add vulnerability nodes
        for vuln in evidence_data.get('vulnerabilities', []):
            title = vuln.get('title', 'Unknown')
            severity = vuln.get('severity', 'info')
            
            severity_scores = {'critical': 1.0, 'high': 0.85, 'medium': 0.6, 'low': 0.3, 'info': 0.1}
            
            vuln_node = self.add_node(
                NODE_VULNERABILITY,
                label=title,
                properties={
                    'title': title,
                    'severity': severity,
                    'cve': vuln.get('cve', ''),
                    'description': vuln.get('description', ''),
                },
                value_score=severity_scores.get(severity, 0.5),
                difficulty_score=0.3,  # Vulnerabilities reduce difficulty
                source='vuln_scan'
            )
        
        self._paths_dirty = True
    
    def summary(self) -> str:
        """Generate human-readable summary of the attack graph."""
        lines = ["ATTACK GRAPH SUMMARY:", "=" * 40]
        
        lines.append(f"Nodes: {len(self._nodes)} | Edges: {len(self._edges)}")
        
        # Count by type
        type_counts: Dict[str, int] = {}
        for node in self._nodes.values():
            type_counts[node.node_type] = type_counts.get(node.node_type, 0) + 1
        
        lines.append("\nNodes by type:")
        for node_type, count in sorted(type_counts.items()):
            lines.append(f"  {node_type}: {count}")
        
        # Top paths
        paths = self.find_paths(max_length=4)
        if paths:
            lines.append("\nTop Attack Paths:")
            for i, path in enumerate(paths[:3], 1):
                lines.append(f"  {i}. {path.description}")
                lines.append(f"     Value: {path.total_value:.2f}, Difficulty: {path.cumulative_difficulty:.2f}, Success: {path.success_probability:.2f}")
        
        # Entry points
        entry_points = self.get_entry_points()
        if entry_points:
            lines.append(f"\nEntry Points: {len(entry_points)}")
            for ep in entry_points[:3]:
                lines.append(f"  - {ep.label} (priority: {ep.priority:.2f})")
        
        # High-value targets
        targets = self.get_high_value_targets()
        if targets:
            lines.append(f"\nHigh-Value Targets: {len(targets)}")
            for t in targets[:3]:
                lines.append(f"  - {t.label} (value: {t.value_score:.2f})")
        
        return "\n".join(lines)
