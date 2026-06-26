from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class EvidenceRecord:
    source: str
    summary: str
    command_id: str = ""
    confidence: float = 0.5
    timestamp: str = field(default_factory=utc_now)


@dataclass
class ServiceRecord:
    port: int
    proto: str = "tcp"
    service: str = ""
    version: str = ""
    state: str = "open"
    confidence: float = 0.7

    @property
    def key(self) -> str:
        return f"{self.port}/{self.proto}"


@dataclass
class EndpointRecord:
    url: str
    method: str = "GET"
    status: int = 0
    params: str = ""
    tech: str = ""
    confidence: float = 0.6


@dataclass
class CredentialRecord:
    service: str
    username: str
    secret_ref: str = ""
    source: str = ""
    confidence: float = 0.4


@dataclass
class VulnerabilityRecord:
    title: str
    severity: str = "info"
    description: str = ""
    evidence: List[EvidenceRecord] = field(default_factory=list)
    confidence: float = 0.4


@dataclass
class HostRecord:
    hostname: str = ""
    ip_addresses: List[str] = field(default_factory=list)
    os_info: str = ""
    services: Dict[str, ServiceRecord] = field(default_factory=dict)
    technologies: Dict[str, str] = field(default_factory=dict)
    endpoints: Dict[str, EndpointRecord] = field(default_factory=dict)
    credentials: List[CredentialRecord] = field(default_factory=list)
    vulnerabilities: List[VulnerabilityRecord] = field(default_factory=list)


@dataclass
class Observation:
    kind: str
    source: str
    data: Dict[str, Any]
    confidence: float = 0.5
    timestamp: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class WorldModelSnapshot:
    target: str
    hosts: int
    services: int
    endpoints: int
    credentials: int
    vulnerabilities: int
    technologies: int
    observations: int

    def summary(self) -> str:
        return (
            f"target={self.target} hosts={self.hosts} services={self.services} "
            f"endpoints={self.endpoints} creds={self.credentials} "
            f"vulns={self.vulnerabilities} tech={self.technologies} obs={self.observations}"
        )


@dataclass
class WorldModel:
    """Structured reasoning state for future cognitive subsystems.

    This wrapper can be rebuilt from the legacy TargetModel at any time, which
    keeps migration safe while new modules learn to consume structured state.
    """

    target: str = ""
    hosts: Dict[str, HostRecord] = field(default_factory=dict)
    observations: List[Observation] = field(default_factory=list)
    confidence: float = 0.0
    provenance: str = ""
    completed_checks: List[str] = field(default_factory=list)
    remaining_unknowns: List[str] = field(default_factory=list)
    candidate_attack_paths: List[Dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_legacy(cls, model: Any) -> "WorldModel":
        target = getattr(model, "hostname", "") or ""
        wm = cls(target=target)
        host = wm.ensure_host(target or "unknown")
        host.ip_addresses = list(getattr(model, "ip_addresses", []) or [])
        host.os_info = getattr(model, "os_info", "") or ""

        for port in getattr(model, "ports", []) or []:
            service = ServiceRecord(
                port=int(port.get("port", 0) or 0),
                proto=port.get("proto", "tcp") or "tcp",
                service=port.get("service", "") or "",
                version=port.get("version", "") or "",
                state=port.get("state", "open") or "open",
            )
            host.services[service.key] = service

        for name, version in (getattr(model, "tech_stack", {}) or {}).items():
            host.technologies[str(name)] = str(version or "")

        for endpoint in getattr(model, "endpoints", []) or []:
            url = endpoint.get("url", "")
            if not url:
                continue
            host.endpoints[f"{endpoint.get('method', 'GET')} {url}"] = EndpointRecord(
                url=url,
                method=endpoint.get("method", "GET") or "GET",
                status=int(endpoint.get("status", 0) or 0),
                params=endpoint.get("params", "") or "",
                tech=endpoint.get("tech", "") or "",
            )

        for cred in getattr(model, "credentials", []) or []:
            host.credentials.append(CredentialRecord(
                service=cred.get("service", "") or "",
                username=cred.get("username", "") or "",
                secret_ref="legacy:credential",
                source=cred.get("source", "") or "",
            ))

        for finding in getattr(model, "findings", []) or []:
            if isinstance(finding, dict):
                title = finding.get("title", "")
                severity = finding.get("severity", "info")
                description = finding.get("detail", "") or finding.get("description", "")
                evidence_text = finding.get("evidence", "")
            else:
                title = getattr(finding, "title", "")
                severity = getattr(finding, "severity", "info")
                description = getattr(finding, "description", "")
                evidence_text = getattr(finding, "evidence", "")
            evidence = []
            if evidence_text:
                evidence.append(EvidenceRecord(source="legacy", summary=str(evidence_text)[:500], confidence=0.6))
            host.vulnerabilities.append(VulnerabilityRecord(
                title=title or "(untitled)",
                severity=severity or "info",
                description=description or "",
                evidence=evidence,
                confidence=0.5 if evidence else 0.3,
            ))

        for subdomain in sorted(getattr(model, "subdomains", set()) or []):
            wm.ensure_host(subdomain)

        return wm

    def ensure_host(self, hostname: str) -> HostRecord:
        key = hostname or "unknown"
        if key not in self.hosts:
            self.hosts[key] = HostRecord(hostname=key)
        return self.hosts[key]

    def ingest(self, observation: Observation):
        self.observations.append(observation)

    def snapshot(self) -> WorldModelSnapshot:
        hosts = list(self.hosts.values())
        return WorldModelSnapshot(
            target=self.target,
            hosts=len(hosts),
            services=sum(len(h.services) for h in hosts),
            endpoints=sum(len(h.endpoints) for h in hosts),
            credentials=sum(len(h.credentials) for h in hosts),
            vulnerabilities=sum(len(h.vulnerabilities) for h in hosts),
            technologies=sum(len(h.technologies) for h in hosts),
            observations=len(self.observations),
        )

    def evidence(self) -> Iterable[EvidenceRecord]:
        for host in self.hosts.values():
            for vuln in host.vulnerabilities:
                yield from vuln.evidence

    def mark_check_complete(self, check: str):
        if check and check not in self.completed_checks:
            self.completed_checks.append(check)

    def add_unknown(self, unknown: str):
        if unknown and unknown not in self.remaining_unknowns:
            self.remaining_unknowns.append(unknown)

    def add_attack_path(self, path: Dict[str, Any]):
        if path:
            self.candidate_attack_paths.append(path)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "confidence": self.confidence,
            "provenance": self.provenance,
            "completed_checks": list(self.completed_checks),
            "remaining_unknowns": list(self.remaining_unknowns),
            "candidate_attack_paths": list(self.candidate_attack_paths),
            "snapshot": self.snapshot().__dict__,
            "hosts": {
                name: {
                    "hostname": host.hostname,
                    "ip_addresses": host.ip_addresses,
                    "os_info": host.os_info,
                    "services": {k: v.__dict__ for k, v in host.services.items()},
                    "technologies": host.technologies,
                    "endpoints": {k: v.__dict__ for k, v in host.endpoints.items()},
                    "credentials": [c.__dict__ for c in host.credentials],
                    "vulnerabilities": [
                        {
                            "title": v.title,
                            "severity": v.severity,
                            "description": v.description,
                            "confidence": v.confidence,
                            "evidence": [e.__dict__ for e in v.evidence],
                        }
                        for v in host.vulnerabilities
                    ],
                }
                for name, host in self.hosts.items()
            },
            "observations": [o.__dict__ for o in self.observations],
        }
