#!/usr/bin/env python3
"""
X19Debugger — standalone diagnostic & self-healing tool for x19.py.

Usage:
    python x19debugger.py scan        # Scan for issues (no changes)
    python x19debugger.py fix         # Scan + auto-fix where possible
    python x19debugger.py check       # Quick health check (syntax + imports)
    python x19debugger.py stats       # Source code statistics

Runs independently — no imports from x19.py.
"""

import ast
import json
import os
import re
import sys
import builtins
import difflib
import textwrap
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set
from datetime import datetime


X19_PATH = Path(__file__).resolve().parent / "agent.py"
BACKUP_DIR = Path(__file__).resolve().parent / ".x19debugger_backups"
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

MAX_LINE_LENGTH = 200
MAX_FUNCTION_LINES = 300
MAX_CLASS_LINES = 1000

COLOR = False
if hasattr(sys.stderr, 'isatty') and sys.stderr.isatty():
    if sys.platform != 'win32' or os.environ.get('TERM'):
        COLOR = True

C = type('C', (), {
    'R': '\033[91m' if COLOR else '',
    'G': '\033[92m' if COLOR else '',
    'Y': '\033[93m' if COLOR else '',
    'B': '\033[94m' if COLOR else '',
    'M': '\033[95m' if COLOR else '',
    'N': '\033[0m' if COLOR else '',
})()


class Issue:
    def __init__(self, severity: str, category: str, line: int, message: str, fix: Optional[callable] = None):
        self.severity = severity
        self.category = category
        self.line = line
        self.message = message
        self._fix = fix
        self.fixed = False

    def can_fix(self) -> bool:
        return self._fix is not None

    def apply(self, lines: list) -> bool:
        if self._fix:
            try:
                result = self._fix(lines)
                if result:
                    self.fixed = True
                    return True
            except Exception:
                pass
        return False

    def __str__(self) -> str:
        tag = {'high': f'{C.R}HIGH{C.N}', 'medium': f'{C.Y}MED{C.N}', 'low': f'{C.B}LOW{C.N}', 'info': f'{C.G}INFO{C.N}'}
        auto = ' [AUTO-FIX]' if self.can_fix() else ''
        return f"  {tag.get(self.severity, self.severity):12s} | L{self.line:<5d} | {self.category:20s} | {self.message}{auto}"


class X19Debugger:
    def __init__(self, source_path: Path = X19_PATH):
        self.source_path = source_path
        self.source = ""
        self.lines: list = []
        self.tree: Optional[ast.Module] = None
        self.issues: List[Issue] = []
        self.modified = False

    # ------------------------------------------------------------------ #
    #  PARSE                                                             #
    # ------------------------------------------------------------------ #

    def load(self) -> bool:
        if not self.source_path.exists():
            print(f"{C.R}[!] x19.py not found at {self.source_path}{C.N}")
            return False
        raw = self.source_path.read_bytes()
        if raw[:3] == b'\xef\xbb\xbf':
            raw = raw[3:]
        self.source = raw.decode("utf-8")
        self.lines = self.source.splitlines(keepends=True)
        try:
            self.tree = ast.parse(self.source)
            return True
        except SyntaxError as e:
            self.issues.append(Issue("high", "syntax", 0, f"SyntaxError: {e}"))
            return False

    # ------------------------------------------------------------------ #
    #  ANALYZERS                                                         #
    # ------------------------------------------------------------------ #

    def check_syntax(self):
        if self.tree is None:
            try:
                self.tree = ast.parse(self.source)
            except SyntaxError as e:
                self.issues.append(Issue("high", "syntax", e.lineno or 0,
                                          f"SyntaxError: {e.msg} (line {e.lineno})"))

    def check_line_length(self):
        for i, line in enumerate(self.lines, 1):
            stripped = line.rstrip('\n\r')
            if len(stripped) > MAX_LINE_LENGTH:
                self.issues.append(Issue("low", "line_length", i,
                                          f"Line too long ({len(stripped)} > {MAX_LINE_LENGTH})"))

    def check_unused_imports(self):
        if not self.tree:
            return
        imports: Dict[str, int] = {}
        import_lines: Dict[str, int] = {}

        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name
                    imports[name] = 0
                    import_lines[name] = node.lineno
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    name = alias.asname or alias.name
                    imports[name] = 0
                    import_lines[name] = node.lineno

        if not imports:
            return

        source_lower = self.source.lower()
        for name, _ in list(imports.items()):
            base = name.split('.')[0]
            if base in builtins.__dict__:
                continue
            count = source_lower.count(base.lower())
            import_line = import_lines[name]
            line_text = self.lines[import_line - 1].lower() if import_line <= len(self.lines) else ""
            count -= line_text.count(base.lower())
            for s in ('__main__', '__future__', 'typing', 'abc', 'dataclasses', 'collections'):
                if name.startswith(s):
                    count = max(count, 1)
            if count <= 0:
                self.issues.append(Issue("medium", "unused_import", import_lines.get(name, 0),
                                          f"Unused import: {name}"))

    def check_undefined_names(self):
        if not self.tree:
            return
        defined: Set[str] = set()
        used: Set[str] = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ClassDef):
                defined.add(node.name)
                for item in node.body:
                    if isinstance(item, ast.FunctionDef):
                        defined.add(item.name)
            elif isinstance(node, ast.FunctionDef):
                defined.add(node.name)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                if node.id not in ('True', 'False', 'None'):
                    used.add(node.id)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        defined.add(target.id)
        known = {'self', 'cls', 'args', 'kwargs', 'log', '_swallow', 'C', 'ICO', 'CONFIG',
                 'BANNER', 'TOOLS', 'COMMON_TOOLS', 'PROVIDERS', 'BLOCKED',
                 'AUTH_ATTACK_PATTERNS', 'EXPLOIT_SUCCESS_PATTERNS', 'OPENAI_COMPAT_PROVIDERS',
                 'PROXY_TYPES', 'TARGET_PATTERNS'}
        known |= set(dir(builtins))
        known |= {'str', 'int', 'float', 'bool', 'list', 'dict', 'tuple', 'set'}
        undefined = used - defined - known
        if undefined:
            undef_lines = []
            full_text = self.source
            for name in sorted(undefined)[:20]:
                pattern = rf'\b{re.escape(name)}\b'
                m = re.search(pattern, full_text)
                if m:
                    line_no = full_text[:m.start()].count('\n') + 1
                    undef_lines.append((line_no, name))
            for line_no, name in undef_lines[:15]:
                self.issues.append(Issue("medium", "undefined", line_no,
                                          f"Possibly undefined name: '{name}'"))

    def check_duplicate_code(self):
        if not self.tree:
            return
        func_bodies: Dict[str, str] = {}
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.body and hasattr(node, 'end_lineno') and node.end_lineno:
                    body = ''.join(self.lines[node.body[0].lineno - 1: node.end_lineno - 1])
                    normalized = re.sub(r'\s+', ' ', body).strip()
                    func_bodies[node.name] = normalized
        names = list(func_bodies.keys())
        checked = set()
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                key = (names[i], names[j]) if names[i] < names[j] else (names[j], names[i])
                if key in checked:
                    continue
                checked.add(key)
                if func_bodies[names[i]] and func_bodies[names[j]] and len(func_bodies[names[i]]) > 50:
                    ratio = difflib.SequenceMatcher(None, func_bodies[names[i]], func_bodies[names[j]]).ratio()
                    if ratio > 0.85:
                        self.issues.append(Issue("medium", "duplicate", 0,
                                                  f"High similarity ({ratio:.0%}) between '{names[i]}' and '{names[j]}'"))

    def check_bare_excepts(self):
        for i, line in enumerate(self.lines, 1):
            stripped = line.strip()
            if stripped == 'except:' or stripped.startswith('except :'):
                self.issues.append(Issue("high", "bare_except", i,
                                          "Bare 'except:' — catches all exceptions silently"))

    def check_todo_fixme(self):
        for i, line in enumerate(self.lines, 1):
            if re.search(r'\b(TODO|FIXME|HACK|XXX|BUG)\b', line, re.IGNORECASE) and not line.strip().startswith('#'):
                pass
            elif re.search(r'\b(TODO|FIXME|HACK|XXX|BUG)\b', line, re.IGNORECASE):
                match = re.search(r'\b(TODO|FIXME|HACK|XXX|BUG)\b', line, re.IGNORECASE)
                if match:
                    self.issues.append(Issue("info", "todo", i,
                                              f"Tag: {match.group()}"))

    def check_section_size(self):
        sections: List[Tuple[str, int, int]] = []
        current_section = "HEADER"
        current_start = 1
        for i, line in enumerate(self.lines, 1):
            m = re.match(r'^# ={5,}\s*(.*?)\s*=+\s*$', line)
            if m:
                sections.append((current_section, current_start, i - 1))
                current_section = m.group(1)
                current_start = i
        sections.append((current_section, current_start, len(self.lines)))
        for name, start, end in sections[1:]:
            size = end - start + 1
            if size > MAX_CLASS_LINES:
                sev = "medium" if size < 2000 else "high"
                self.issues.append(Issue(sev, "big_section", start,
                                          f"Section '{name}' is {size} lines (consider splitting)"))

    def check_print_statements(self):
        if not self.tree:
            return
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'print':
                continue

    def check_mixed_indentation(self):
        for i, line in enumerate(self.lines, 1):
            if not line.strip() or line.strip().startswith('#'):
                continue
            if '\t' in line:
                self.issues.append(Issue("medium", "indentation", i,
                                          "Line contains tabs (use spaces)"))

    def check_long_functions(self):
        if not self.tree:
            return
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if hasattr(node, 'end_lineno') and node.end_lineno:
                    size = node.end_lineno - node.lineno
                    if size > MAX_FUNCTION_LINES:
                        self.issues.append(Issue("medium", "long_function", node.lineno,
                                                  f"Function '{node.name}' is {size} lines (>{MAX_FUNCTION_LINES})"))

    def scan(self) -> List[Issue]:
        self.issues = []
        if not self.load():
            return self.issues
        self.check_syntax()
        self.check_line_length()
        self.check_unused_imports()
        self.check_undefined_names()
        self.check_bare_excepts()
        self.check_todo_fixme()
        self.check_section_size()
        self.check_mixed_indentation()
        self.check_long_functions()
        return self.issues

    # ------------------------------------------------------------------ #
    #  FIXES                                                             #
    # ------------------------------------------------------------------ #

    def fix_bare_excepts(self) -> int:
        count = 0
        new_lines = []
        for line in self.lines:
            stripped = line.strip()
            if stripped == 'except:' or stripped.startswith('except :'):
                indent = line[:len(line) - len(line.lstrip())]
                new_lines.append(f"{indent}except Exception:\n")
                count += 1
            else:
                new_lines.append(line)
        if count:
            self.source = ''.join(new_lines)
            self.lines = new_lines
            self.modified = True
        return count

    def fix_indentation(self) -> int:
        count = 0
        new_lines = []
        for line in self.lines:
            if '\t' in line and not line.strip().startswith('#'):
                new_lines.append(line.replace('\t', '    '))
                count += 1
            else:
                new_lines.append(line)
        if count:
            self.source = ''.join(new_lines)
            self.lines = new_lines
            self.modified = True
        return count

    def fix_trailing_whitespace(self) -> int:
        count = 0
        new_lines = []
        for line in self.lines:
            stripped = line.rstrip('\n\r')
            clean = stripped.rstrip()
            if clean != stripped:
                suffix = '\n' if line.endswith('\n') else ''
                new_lines.append(clean + suffix)
                count += 1
            else:
                new_lines.append(line)
        if count:
            self.source = ''.join(new_lines)
            self.lines = new_lines
            self.modified = True
        return count

    def fix_missing_newline(self) -> bool:
        if self.source and not self.source.endswith('\n'):
            self.source += '\n'
            self.lines = self.source.splitlines(keepends=True)
            self.modified = True
            return True
        return False

    def auto_fix(self) -> int:
        fixed = 0
        fixed += self.fix_bare_excepts()
        fixed += self.fix_indentation()
        fixed += self.fix_trailing_whitespace()
        fixed += 1 if self.fix_missing_newline() else 0
        return fixed

    # ------------------------------------------------------------------ #
    #  SAVE & BACKUP                                                     #
    # ------------------------------------------------------------------ #

    def backup(self) -> Optional[Path]:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = BACKUP_DIR / f"x19_backup_{ts}.py"
        backup_path.write_text(self.source_path.read_text(encoding="utf-8"), encoding="utf-8")
        return backup_path

    def save(self) -> bool:
        if not self.modified:
            return False
        backup = self.backup()
        self.source_path.write_bytes(self.source.encode("utf-8"))
        print(f"{C.G}[+] Backup saved: {backup}{C.N}")
        print(f"{C.G}[+] Changes written to {self.source_path}{C.N}")
        return True

    # ------------------------------------------------------------------ #
    #  STATS                                                             #
    # ------------------------------------------------------------------ #

    def stats(self):
        if not self.load():
            return
        lines = len(self.lines)
        source = self.source
        non_blank = sum(1 for l in self.lines if l.strip())
        classes = len([n for n in ast.walk(self.tree) if isinstance(n, ast.ClassDef)])
        funcs = len([n for n in ast.walk(self.tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))])
        imports = len([n for n in ast.walk(self.tree) if isinstance(n, (ast.Import, ast.ImportFrom))])
        chars = len(source)
        print(f"\n{C.B}{'='*40}{C.N}")
        print(f"{C.B}   X19 Source Statistics{C.N}")
        print(f"{C.B}{'='*40}{C.N}")
        print(f"  File        : {self.source_path}")
        print(f"  Lines       : {lines:,}")
        print(f"  Non-blank   : {non_blank:,}")
        print(f"  Characters  : {chars:,}")
        print(f"  Classes     : {classes}")
        print(f"  Functions   : {funcs}")
        print(f"  Imports     : {imports}")
        print(f"  Avg line len: {chars // max(lines, 1)}")
        sections = []
        for i, line in enumerate(self.lines, 1):
            m = re.match(r'^# ={5,}\s*(.*?)\s*=+\s*$', line)
            if m:
                sections.append((m.group(1), i))
        if sections:
            print(f"\n  Sections ({len(sections)}):")
            for name, ln in sections:
                print(f"    L{ln:<6d} {name}")
        print()

    # ------------------------------------------------------------------ #
    #  REPORT                                                            #
    # ------------------------------------------------------------------ #

    def print_report(self, issues: List[Issue]):
        if not issues:
            print(f"\n{C.G}[+] No issues found. Clean!{C.N}\n")
            return
        by_sev = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for iss in issues:
            by_sev[iss.severity] = by_sev.get(iss.severity, 0) + 1
        print(f"\n{C.B}{'='*40}{C.N}")
        print(f"{C.B}   X19Debugger Report{C.N}")
        print(f"{C.B}{'='*40}{C.N}")
        print(f"  Total issues: {len(issues)}")
        print(f"  {C.R}High  : {by_sev.get('high', 0)}{C.N}")
        print(f"  {C.Y}Medium: {by_sev.get('medium', 0)}{C.N}")
        print(f"  {C.B}Low   : {by_sev.get('low', 0)}{C.N}")
        print(f"  {C.G}Info  : {by_sev.get('info', 0)}{C.N}")
        print()
        for iss in issues:
            print(iss)
        print()


def cmd_scan(debugger: X19Debugger):
    issues = debugger.scan()
    debugger.print_report(issues)


def cmd_fix(debugger: X19Debugger):
    issues = debugger.scan()
    debugger.print_report(issues)
    auto_fixable = [i for i in issues if i.can_fix()]
    if auto_fixable:
        print(f"\n{C.Y}[*] {len(auto_fixable)} issues are auto-fixable.{C.N}")
        for iss in auto_fixable:
            if iss.apply(debugger.lines):
                print(f"  {C.G}[+] Fixed: L{iss.line} — {iss.message}{C.N}")
    fixed = debugger.auto_fix()
    if fixed:
        print(f"{C.G}[+] {fixed} auto-fixes applied{C.N}")
        debugger.save()
    else:
        manual = [i for i in issues if not i.can_fix()]
        if manual:
            print(f"{C.Y}[*] {len(manual)} issues require manual fixes{C.N}")
        else:
            print(f"{C.G}[+] Everything is clean!{C.N}")


def cmd_check(debugger: X19Debugger):
    print(f"{C.B}[*] Syntax check...{C.N}", end=" ")
    raw = debugger.source_path.read_bytes()
    if raw[:3] == b'\xef\xbb\xbf':
        raw = raw[3:]
    try:
        ast.parse(raw.decode("utf-8"))
        print(f"{C.G}OK{C.N}")
    except SyntaxError as e:
        print(f"{C.R}FAIL: {e}{C.N}")
        return
    debugger.load()
    imports = [n for n in ast.walk(debugger.tree) if isinstance(n, (ast.Import, ast.ImportFrom))]
    print(f"{C.B}[*] Imports: {len(imports)} total{C.N}")
    for imp in imports[:5]:
        if isinstance(imp, ast.Import):
            print(f"    import {', '.join(a.name for a in imp.names)}")
        else:
            print(f"    from {imp.module} import {', '.join(a.name for a in imp.names)}")
    if len(imports) > 5:
        print(f"    ... and {len(imports) - 5} more")
    classes = len([n for n in ast.walk(debugger.tree) if isinstance(n, ast.ClassDef)])
    funcs = len([n for n in ast.walk(debugger.tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))])
    print(f"{C.B}[*] Classes: {classes}, Functions: {funcs}{C.N}")
    print(f"{C.G}[+] Health check passed{C.N}")


def cmd_stats(debugger: X19Debugger):
    debugger.stats()


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="X19Debugger — analyze and fix issues in x19.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python x19debugger.py scan     # Scan for issues (read-only)
              python x19debugger.py fix      # Auto-fix found issues
              python x19debugger.py check    # Quick health check
              python x19debugger.py stats    # Source code statistics
        """))
    parser.add_argument("command", nargs="?", default="scan",
                        choices=["scan", "fix", "check", "stats"],
                        help="Action to perform (default: scan)")
    args = parser.parse_args()

    debugger = X19Debugger()

    if args.command == "scan":
        cmd_scan(debugger)
    elif args.command == "fix":
        cmd_fix(debugger)
    elif args.command == "check":
        cmd_check(debugger)
    elif args.command == "stats":
        cmd_stats(debugger)


if __name__ == "__main__":
    main()
