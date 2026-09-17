"""
Skill Loader — RedTeam-Agent (ktol1) skill-first + PentestCode 19-skills pattern.

Loads markdown skill packs from:
  - skills/*.md          (user/project skills, highest priority)
  - builtin_skills/*.md  (shipped fallback)
  - ~/.x19/skills/*.md   (global, optional)

Each skill file is a markdown with front-matter style header:
  # Skill: nmap_scan
  **Category:** recon
  **Tools:** nmap, masscan
  **When:** open ports unknown
  
  ## Procedure
  1. ...

The loader:
 - token-optimizes: strips verbose examples, keeps Procedure + When + Tools, caps 3k per skill
 - exposes `list_skills()`, `get_skill(name)`, `suggest_skills(task) -> ranked`
 - integrates with MCP gateway: `skill.to_tool_spec()`

If no skills dir exists, falls back to 6 built-in minimal skills (recon, web, vuln, creds, ad, reporting)
so the system is not empty.

Usage:
  from brain.skill_loader import SkillLoader
  loader = SkillLoader()
  for s in loader.list_skills(): print(s.name, s.category)
  plan = loader.suggest_skills("enumerate subdomains and find sqli")
"""

from __future__ import annotations

import re
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

@dataclass
class Skill:
    name: str
    category: str
    tools: List[str]
    when: str
    procedure: str
    raw: str
    path: str
    tokens_estimate: int = 0

    def to_tool_spec(self) -> Dict[str, Any]:
        return {"name": self.name, "category": self.category, "tools": self.tools, "when": self.when, "procedure": self.procedure}

    def compact(self, max_chars: int = 3000) -> str:
        # token-optimized: When + Tools + Procedure only
        txt = f"# {self.name} ({self.category})\nTools: {', '.join(self.tools)}\nWhen: {self.when}\n\n{self.procedure}"
        if len(txt) > max_chars:
            txt = txt[:max_chars] + "\n...[truncated]"
        return txt

BUILTIN_SKILLS: List[Dict[str, str]] = [
    {"name":"recon_surface", "category":"recon", "tools":"nmap,naabu,httpx,subfinder,amass", "when":"initial recon, unknown attack surface", "procedure":"1. subfinder -d {domain} -silent\n2. httpx -l subs.txt -tech-detect -status-code\n3. naabu -host {target} -top-ports 1000\n4. nmap -sV -p <open> {target}\nPersist via EngagementStore state_update."},
    {"name":"web_crawl", "category":"web", "tools":"katana,httpx,whatweb", "when":"web service discovered", "procedure":"1. katana -u {target} -jc -silent\n2. httpx -u {target} -tech-detect\n3. whatweb {target}\nFeed endpoints to world_model + blackboard."},
    {"name":"vuln_scan", "category":"vuln", "tools":"nuclei,dalfox,sqlmap", "when":"endpoints with params discovered", "procedure":"1. nuclei -u {target} -severity medium,high,critical\n2. dalfox url {target}?param=FUZZ --silence\n3. sqlmap --batch --level 1 --risk 1 (only with auth gate)\nReport only with PoC."},
    {"name":"creds_hunt", "category":"creds", "tools":"trufflehog,hashcat", "when":"repo/files or login forms found", "procedure":"1. trufflehog filesystem {path} --only-verified=false\n2. test creds against endpoints (rate-limited)\nStore in EngagementStore credentials."},
    {"name":"ad_enum", "category":"ad", "tools":"nxc,kerbrute,SharpHound,bloodhound", "when":"AD / SMB / Kerberos service detected", "procedure":"1. nxc smb {target} --users\n2. kerbrute userenum --dc {dc} -d {domain} users.txt\n3. SharpHound collector + BloodHound analysis\nRequires ScopeGuard pass."},
    {"name":"report_and_fix", "category":"reporting", "tools":"sarif,autofix", "when":"findings verified", "procedure":"1. generate sarif via reporting/sarif.py\n2. triage+group via reporting/autofix.py\n3. draft PR + verify_after_fix"},
]

class SkillLoader:
    def __init__(self, search_paths: Optional[List[Path]] = None):
        if search_paths is not None:
            self.search_paths = [Path(p) for p in search_paths]
        else:
            self.search_paths = [Path("skills"), Path("builtin_skills"), Path.home() / ".x19" / "skills"]
        self._skills: Dict[str, Skill] = {}
        self._load()

    def _load(self):
        self._skills.clear()
        # builtins always present
        for b in BUILTIN_SKILLS:
            s = Skill(name=b["name"], category=b["category"], tools=[t.strip() for t in b["tools"].split(",")], when=b["when"], procedure=b["procedure"], raw=b["procedure"], path="<builtin>", tokens_estimate=len(b["procedure"].split()))
            self._skills[s.name] = s
        # disk skills override / extend
        for base in self.search_paths:
            if not base.exists() or not base.is_dir():
                continue
            for md in sorted(base.glob("*.md")):
                try:
                    raw = md.read_text(errors="ignore")
                    skill = self._parse_markdown(raw, str(md))
                    if skill:
                        self._skills[skill.name] = skill
                except Exception:
                    continue

    def _parse_markdown(self, raw: str, path: str) -> Optional[Skill]:
        # parse name
        m = re.search(r"^#\s+Skill:\s*(.+)$", raw, re.M)
        if not m:
            m = re.search(r"^#\s+(.+)$", raw, re.M)
        name = (m.group(1).strip() if m else Path(path).stem).lower().replace(" ","_")[:48]
        cat_m = re.search(r"\*\*Category:\*\*\s*(.+)", raw)
        category = cat_m.group(1).strip().lower() if cat_m else "generic"
        tools_m = re.search(r"\*\*Tools:\*\*\s*(.+)", raw)
        tools = [t.strip() for t in (tools_m.group(1).split(",") if tools_m else []) if t.strip()]
        when_m = re.search(r"\*\*When:\*\*\s*(.+)", raw)
        when = when_m.group(1).strip() if when_m else ""
        # procedure = ## Procedure block or rest after header
        proc_m = re.search(r"##\s*Procedure\s*\n(.+)", raw, re.S)
        procedure = proc_m.group(1).strip() if proc_m else raw[:3000]
        # token-optimize: limit
        if len(procedure) > 3000:
            procedure = procedure[:3000] + "\n...[truncated for token optimization]"
        return Skill(name=name, category=category, tools=tools, when=when, procedure=procedure, raw=raw, path=path, tokens_estimate=len(procedure.split()))

    def list_skills(self) -> List[Skill]:
        return sorted(self._skills.values(), key=lambda s: s.name)

    def get_skill(self, name: str) -> Optional[Skill]:
        return self._skills.get(name.lower().replace(" ","_"))

    def suggest_skills(self, task: str = "", category: str = "") -> List[Skill]:
        task_l = (task or "").lower()
        cat_l = (category or "").lower()
        scored: List[tuple[int, Skill]] = []
        for s in self._skills.values():
            score = 0
            if cat_l and s.category == cat_l:
                score += 10
            if task_l:
                # keyword overlap
                for kw in re.findall(r"\w+", task_l):
                    if len(kw) < 3: continue
                    if kw in s.name.lower(): score += 3
                    if kw in s.category.lower(): score += 2
                    if kw in " ".join(s.tools).lower(): score += 2
                    if kw in s.when.lower(): score += 1
                    if kw in s.procedure.lower(): score += 1
            scored.append((score, s))
        scored.sort(key=lambda x: x[0], reverse=True)
        # return top 5 with score>0, or top 3 generic
        filtered = [s for sc, s in scored if sc > 0]
        return filtered[:5] if filtered else [s for _, s in scored[:3]]

    def token_optimized_prompt(self, task: str = "") -> str:
        """Compact prompt injection for LLM (RedTeam-Agent token optimization)."""
        skills = self.suggest_skills(task) if task else self.list_skills()[:4]
        parts = ["## Available Skills (token-optimized)"]
        for s in skills:
            parts.append(s.compact(max_chars=800))
        return "\n\n".join(parts)

# convenience singleton
_LOADER: Optional[SkillLoader] = None

def get_skill_loader() -> SkillLoader:
    global _LOADER
    if _LOADER is None:
        _LOADER = SkillLoader()
    return _LOADER
