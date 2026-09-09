#!/usr/bin/env python3
"""CLI surface for X19's Hermes-inspired runtime capabilities."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import List

from config import CONFIG
from runtime.hermes_runtime import CronStore, SessionRecall, Skill, SkillStore, SubagentPool


COMMANDS = {"runtime", "skills", "skill", "recall", "delegate", "cron"}


def _json_or_print(args, payload, text: str = "") -> int:
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
    elif text:
        print(text)
    else:
        print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
    return 0


def cmd_runtime(args) -> int:
    skills = SkillStore(CONFIG.SKILLS_DIR)
    cron = CronStore(CONFIG.CRON_JOBS_FILE)
    recall = SessionRecall(CONFIG.SESSION_INDEX_DB)
    payload = {
        "runtime": "hermes-inspired",
        "skills": {"directory": str(skills.root), "count": len(skills.list())},
        "session_recall": {"database": str(recall.db_path)},
        "subagents": {
            "max_concurrent": CONFIG.SUBAGENT_MAX_CONCURRENT,
            "max_iterations": CONFIG.SUBAGENT_MAX_ITERATIONS,
            "directory": str(Path(CONFIG.SUBAGENT_DIR).expanduser()),
        },
        "cron": {"jobs_file": str(cron.path), "jobs": len(cron.list()), "poll_seconds": CONFIG.CRON_POLL_SECONDS},
        "learning": {"auto_learn_skills": CONFIG.AUTO_LEARN_SKILLS},
    }
    return _json_or_print(args, payload, "X19 runtime\n" + "\n".join([
        f"  skills       {payload['skills']['count']}  → {payload['skills']['directory']}",
        f"  recall       FTS5 → {payload['session_recall']['database']}",
        f"  subagents    {CONFIG.SUBAGENT_MAX_CONCURRENT} concurrent / {CONFIG.SUBAGENT_MAX_ITERATIONS} iterations",
        f"  cron         {payload['cron']['jobs']} persisted job(s)",
        f"  self-learning {'enabled' if CONFIG.AUTO_LEARN_SKILLS else 'disabled'}",
    ]))


def cmd_skills(args) -> int:
    store = SkillStore(CONFIG.SKILLS_DIR)
    query = getattr(args, "query", "") or ""
    rows = store.search(query, limit=args.limit) if query else store.list()[: args.limit]
    payload = [
        {"name": s.name, "description": s.description, "source": s.source, "uses": s.uses, "successes": s.successes, "failures": s.failures}
        for s in rows
    ]
    text = "\n".join(
        f"{s.name:32} {s.successes:>3} success / {s.uses:>3} uses  {s.description}" for s in rows
    ) or "No skills yet."
    return _json_or_print(args, payload, text)


def cmd_skill(args) -> int:
    store = SkillStore(CONFIG.SKILLS_DIR)
    action = args.action
    if action == "show":
        skill = store.get(args.name)
        if not skill:
            print(f"skill not found: {args.name}", file=sys.stderr)
            return 1
        return _json_or_print(args, skill.__dict__, skill.body)
    if action == "create":
        if store.get(args.name):
            print(f"skill already exists: {args.name}", file=sys.stderr)
            return 1
        body = args.body
        if args.file:
            body = Path(args.file).read_text(encoding="utf-8")
        skill = store.create(args.name, args.description, body, source="user")
        return _json_or_print(args, skill.__dict__, f"created skill: {skill.name}")
    if action == "delete":
        skill = store.get(args.name)
        if not skill:
            return 1
        path = store.root / skill.name / "SKILL.md"
        path.unlink(missing_ok=True)
        try:
            path.parent.rmdir()
        except OSError:
            pass
        return _json_or_print(args, {"deleted": skill.name}, f"deleted skill: {skill.name}")
    return 2


def cmd_recall(args) -> int:
    recall = SessionRecall(CONFIG.SESSION_INDEX_DB)
    rows = recall.search(args.query, limit=args.limit)
    return _json_or_print(args, rows, "\n".join(
        f"{row['session_id']}  {row['target']}  {row['status']}  {row['started']}" for row in rows
    ) or "No matching sessions.")


def cmd_delegate(args) -> int:
    # Delegation is deliberately an analysis-only surface. The existing X19
    # swarm remains responsible for target execution, scope and verification.
    from providers import make_ai

    pool = SubagentPool(
        ai=make_ai(),
        root=CONFIG.SUBAGENT_DIR,
        max_workers=CONFIG.SUBAGENT_MAX_CONCURRENT,
    )
    tasks = []
    for goal in args.goal:
        tasks.append({"goal": goal, "context": args.context, "role": args.role, "max_iterations": CONFIG.SUBAGENT_MAX_ITERATIONS})
    results = pool.run_parallel(tasks, max_workers=args.workers or CONFIG.SUBAGENT_MAX_CONCURRENT)
    payload = [r.__dict__ for r in results]
    text = "\n\n".join(
        f"[{r.status}] {r.goal}\n{r.summary or r.error}\nworkspace={r.workspace}"
        for r in results
    )
    return _json_or_print(args, payload, text)


def cmd_cron(args) -> int:
    store = CronStore(CONFIG.CRON_JOBS_FILE)
    if args.action == "list":
        jobs = [j.__dict__ for j in store.list()]
        return _json_or_print(args, jobs, "\n".join(
            f"{j['id']}  {'on' if j['enabled'] else 'off'}  every {j['interval_seconds']}s  {' '.join(j['command'])}  next={time.ctime(j['next_run'])}"
            for j in jobs
        ) or "No cron jobs.")
    if args.action == "add":
        job = store.add(args.command, args.interval, repeat=args.repeat)
        return _json_or_print(args, job.__dict__, f"created {job.id}: every {job.interval_seconds}s → {' '.join(job.command)}")
    if args.action in {"pause", "resume", "remove"}:
        fn = {"pause": store.pause, "resume": store.resume, "remove": store.remove}[args.action]
        ok = fn(args.job_id)
        return _json_or_print(args, {args.action: ok, "job_id": args.job_id}, f"{args.action}: {'ok' if ok else 'not found'}")
    if args.action == "run":
        jobs = store.run_due()
        return _json_or_print(args, [j.__dict__ for j in jobs], f"ran {len(jobs)} due job(s)")
    if args.action == "daemon":
        print(f"X19 cron daemon running — {store.path}")
        try:
            store.daemon(poll_seconds=CONFIG.CRON_POLL_SECONDS)
        except KeyboardInterrupt:
            pass
        return 0
    return 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="x19 runtime")
    p.add_argument("--json", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("runtime")

    s = sub.add_parser("skills")
    s.add_argument("query", nargs="?", default="")
    s.add_argument("--limit", type=int, default=20)

    s = sub.add_parser("skill")
    s.add_argument("action", choices=["show", "create", "delete"])
    s.add_argument("name")
    s.add_argument("--description", default="")
    s.add_argument("--body", default="")
    s.add_argument("--file", default="")

    s = sub.add_parser("recall")
    s.add_argument("query")
    s.add_argument("--limit", type=int, default=10)

    s = sub.add_parser("delegate")
    s.add_argument("goal", nargs="+")
    s.add_argument("--context", default="")
    s.add_argument("--role", default="leaf")
    s.add_argument("--workers", type=int, default=0)

    s = sub.add_parser("cron")
    s.add_argument("action", choices=["list", "add", "pause", "resume", "remove", "run", "daemon"])
    s.add_argument("job_id", nargs="?", default="")
    s.add_argument("command", nargs="*", default=[])
    s.add_argument("--interval", type=int, default=3600)
    s.add_argument("--repeat", type=int, default=0)

    return p


def dispatch(argv: List[str]) -> int:
    if not argv or argv[0] not in COMMANDS:
        return -1
    # Support both `x19 skills ...` and `x19 runtime skills ...`.
    if argv[0] == "runtime" and len(argv) > 1:
        argv = argv[1:]
    else:
        argv = list(argv)
    args = build_parser().parse_args(argv)
    if args.command == "runtime":
        return cmd_runtime(args)
    if args.command == "skills":
        return cmd_skills(args)
    if args.command == "skill":
        return cmd_skill(args)
    if args.command == "recall":
        return cmd_recall(args)
    if args.command == "delegate":
        return cmd_delegate(args)
    if args.command == "cron":
        return cmd_cron(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(dispatch(sys.argv[1:]))
