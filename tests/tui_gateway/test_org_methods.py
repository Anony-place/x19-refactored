"""The TUI's org surface must project live runtime state — never cached, never filled in.

``tui_gateway/methods_org.py`` calls itself "the TUI's only window into org state"
and promises that "there is no caching layer, no synthetic filler and no 'last known
good' fallback: when the organization has done nothing, the panels show nothing,
which is the truth."

These tests hold it to that promise. Every method is invoked through the real
registration seam (``tui_gateway.server._methods``, populated by
``HandlerRegistry.install`` → ``register_method``), against a real
``OrganizationRuntime``, and asserted against state the test itself created — so a
handler that answered with a plausible constant, a stale copy or an invented roster
would fail. Each payload is also validated against the committed contract in
``tui_gateway/contracts/org.py``; that base forbids extra keys, so the wire shape
the frontend renders is pinned too.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import tui_gateway.server as srv  # noqa: E402
from tui_gateway import methods_org  # noqa: E402
from tui_gateway.contracts.org import (  # noqa: E402
    OrgAgentsResult,
    OrgApprovalResult,
    OrgApprovalsResult,
    OrgAuditResult,
    OrgEventsResult,
    OrgPauseResult,
    OrgRolesResult,
    OrgStatusResult,
    OrgStopResult,
    OrgTaskControlResult,
    OrgTasksResult,
)
from x19.org import (  # noqa: E402
    MANAGER_ROLE_ID,
    Boss,
    Manager,
    OrganizationRuntime,
    RoleKind,
    RoleSpec,
    TaskStatus,
    register_role,
    reset_event_bus,
    reset_roles,
    reset_runtime,
    set_live_reader,
    set_runtime,
    unregister_role,
)

METHODS_ORG_PY = REPO_ROOT / "tui_gateway" / "methods_org.py"

# The surface the console needs: seven reads, and operator authority over the run.
EXPECTED_METHODS = {
    "org.status", "org.audit", "org.agents", "org.roles", "org.tasks",
    "org.events", "org.approvals", "org.approve", "org.deny", "org.pause",
    "org.resume", "org.stop", "org.task.control",
}

# The smallest graph that exercises dependencies, parallelism and convergence.
PLAN = [
    {"key": "impl", "objective": "Implement the CSV export endpoint", "role_id": "coding"},
    {
        "key": "test",
        "objective": "Write and run tests for CSV export",
        "role_id": "testing",
        "depends_on": ["impl"],
    },
    {
        "key": "docs",
        "objective": "Document the CSV export endpoint",
        "role_id": "documentation",
        "depends_on": ["impl"],
    },
]


@pytest.fixture()
def org(tmp_path: Path):
    """A real runtime with a deterministic live-subagent source.

    The delegation engine's live reader is injected so roster assertions test the
    overlay logic rather than whichever children happen to be running.
    """
    live: list[dict] = []
    set_live_reader(lambda: list(live))
    reset_event_bus()

    rt = OrganizationRuntime(root=tmp_path, persist=False)
    set_runtime(rt)

    yield SimpleNamespace(runtime=rt, boss=Boss(rt), manager=Manager(rt), live=live)

    set_live_reader(None)
    reset_runtime()
    reset_event_bus()
    reset_roles()
    # org.pause and org.stop close a process-wide spawn gate in the delegation
    # registry, and reset_runtime() does not reopen it. Left shut, it would leak
    # into every test that runs after this one.
    try:
        from tools.delegate_tool_registry import set_spawn_paused

        set_spawn_paused(False)
    except Exception:
        pass


def _envelope(method: str, params: dict | None = None) -> dict:
    """Invoke a registered RPC method and return the whole JSON-RPC envelope."""
    return srv._methods[method](1, params or {})


def _result(method: str, params: dict | None = None) -> dict:
    envelope = _envelope(method, params)
    assert "error" not in envelope, envelope
    return envelope["result"]


def _plan(org) -> dict:
    org.boss.accept_objective("Build the CSV export feature, test it and document it")
    result = org.manager.plan(PLAN)
    assert result["ok"], result.get("errors")
    return result["keys"]


def _run_to_running(org, task_id: str, role_id: str) -> None:
    org.runtime.tasks.assign(
        task_id, role_id=role_id, manager_id=MANAGER_ROLE_ID, agent_id=role_id
    )
    org.runtime.tasks.start(task_id, agent_id=role_id, subagent_id=f"sa-{role_id}")


def _ids(result: dict, key: str = "filtered") -> list[str]:
    return [row["id"] for row in result[key]]


# ============================================================
# registration — the seam the TUI actually calls
# ============================================================


def test_every_declared_handler_reaches_the_server_registry():
    """A handler that is declared but fails to bind is a panel that never loads."""
    declared = set(re.findall(r'@method\("(org\.[a-z.]+)"\)',
                              METHODS_ORG_PY.read_text(encoding="utf-8")))
    registered = {name for name in srv._methods if name.startswith("org.")}
    assert declared == EXPECTED_METHODS, sorted(declared ^ EXPECTED_METHODS)
    assert registered == declared, sorted(registered ^ declared)


def test_the_handler_module_hardcodes_no_roster():
    """The registry is dynamic, so the wire layer must not carry a baked-in one."""
    body = METHODS_ORG_PY.read_text(encoding="utf-8").split("_registry = HandlerRegistry()", 1)[-1]
    for role in ("coding", "testing", "documentation", "recon", "research",
                 "security", "devops", "analysis"):
        assert f'"{role}"' not in body and f"'{role}'" not in body, role


# ============================================================
# reads — projections, never filler
# ============================================================


def test_an_organization_that_has_done_nothing_projects_nothing(org):
    """The docstring's promise: no synthetic filler when there is no state."""
    tasks = _result("org.tasks")
    OrgTasksResult.model_validate(tasks)
    for slice_name in ("tree", "ready", "blocked", "failed", "in_review"):
        assert tasks[slice_name] == [], slice_name

    assert _result("org.events")["events"] == []
    assert _result("org.approvals")["pending"] == []
    assert _result("org.agents")["live_subagents"] == []
    assert tasks["run"]["phase"] == "idle" and tasks["run"]["active"] is False
    assert _result("org.status")["render"] != ""  # the panel renders; it just has nothing to show


def test_status_projects_the_real_graph_and_the_render_agrees(org):
    ids = _plan(org)
    result = _result("org.status", {"event_limit": 5})
    OrgStatusResult.model_validate(result)

    blob = json.dumps(result["status"], default=str)
    for key in ("impl", "test", "docs"):
        assert ids[key] in blob, f"the status projection lost task {key}"
    assert "coding" in blob and "testing" in blob, "role ids must come from the registry"

    # `render` is the same content as dense text, not a separate source of truth.
    assert ids["impl"] in result["render"] or "CSV export" in result["render"]


def test_accepting_an_objective_opens_a_live_run(org):
    """The run panel is live before any planning: X19 has accepted work."""
    idle = _result("org.tasks")["run"]
    assert idle["run_id"] is None and idle["phase"] == "idle" and idle["active"] is False

    org.boss.accept_objective("Build the CSV export feature")

    run = _result("org.tasks")["run"]
    assert run["objective"] == "Build the CSV export feature"
    assert run["phase"] == "running" and run["active"] is True
    assert run["objective_task_id"]
    # The objective task is itself the running root of the graph, which is why a
    # poll for running work answers before a single step has been planned.
    assert org.runtime.tasks.get(run["objective_task_id"]).status is TaskStatus.RUNNING
    assert run["objective_task_id"] in _ids(_result("org.tasks", {"status": "running"}))


def test_status_is_read_fresh_on_every_call(org):
    """No caching layer: the same method answers differently as state moves."""
    ids = _plan(org)
    assert ids["impl"] in _ids(_result("org.tasks", {"status": "planned"}))
    assert ids["impl"] not in _ids(_result("org.tasks", {"status": "running"}))

    _run_to_running(org, ids["impl"], "coding")

    assert ids["impl"] in _ids(_result("org.tasks", {"status": "running"}))
    assert ids["impl"] not in _ids(_result("org.tasks", {"status": "planned"}))
    assert ids["impl"] in json.dumps(_result("org.status")["status"], default=str)


def test_tasks_status_filter_and_limit_read_the_live_graph(org):
    ids = _plan(org)
    planned = _result("org.tasks", {"status": "planned", "limit": 2})
    OrgTasksResult.model_validate(planned)
    assert planned["filter"] == "planned"
    assert len(planned["filtered"]) <= 2
    assert ids["impl"] in _ids(planned)

    # The filtered slice must agree with the runtime, not with a copy of it.
    from x19.org.tasks import TaskStatus as TS

    assert _ids(planned) == [t.id for t in org.runtime.tasks.by_status(TS.PLANNED)[:2]]


def test_an_unknown_status_filter_is_a_typed_error_listing_the_real_statuses(org):
    envelope = _envelope("org.tasks", {"status": "sideways"})
    assert envelope["error"]["code"] == 4002
    assert TaskStatus.QUEUED.value in envelope["error"]["data"]["valid"]
    assert "sideways" not in envelope["error"]["data"]["valid"]


def test_roles_follow_registration_without_a_code_change(org):
    """Requirement: a dynamic registry, never a frontend-side list."""
    result = _result("org.roles")
    OrgRolesResult.model_validate(result)
    before = [role["id"] for role in result["roles"]]
    assert "localisation" not in before
    assert {"coding", "testing", "documentation"} <= set(before)

    register_role(
        RoleSpec(
            id="localisation",
            kind=RoleKind.WORKER,
            display_name="Localisation",
            title="Localization specialist",
            summary="Translates and localizes product copy.",
            manager_id=MANAGER_ROLE_ID,
            capabilities=("translate",),
        )
    )
    assert "localisation" in [role["id"] for role in _result("org.roles")["roles"]]

    unregister_role("localisation")
    assert "localisation" not in [role["id"] for role in _result("org.roles")["roles"]]


def test_agents_overlay_the_delegation_engines_live_subagents(org):
    result = _result("org.agents")
    OrgAgentsResult.model_validate(result)
    assert result["agents"], "the registered roster is real state, not an empty panel"
    assert result["live_subagents"] == []

    org.live.append({
        "subagent_id": "sa-live",
        "goal": "Implement the CSV export endpoint",
        "status": "running",
        "depth": 1,
    })
    live = _result("org.agents")["live_subagents"]
    assert [row["subagent_id"] for row in live] == ["sa-live"]

    org.live.clear()
    assert _result("org.agents")["live_subagents"] == []


def test_events_are_the_append_only_stream_and_since_seq_polls_incrementally(org):
    ids = _plan(org)
    result = _result("org.events")
    OrgEventsResult.model_validate(result)
    assert result["events"], "planning a real graph must emit real events"

    seqs = [event["seq"] for event in result["events"]]
    assert len(set(seqs)) == len(seqs), "sequence numbers identify events"

    last = result["last_seq"]
    assert _result("org.events", {"since_seq": last})["events"] == [], (
        "polling with the last seq seen must return nothing new"
    )

    _run_to_running(org, ids["impl"], "coding")
    newer = _result("org.events", {"since_seq": last})["events"]
    assert newer, "the transitions just made must show up on the next poll"
    assert all(event["seq"] > last for event in newer)

    only_impl = _result("org.events", {"task_id": ids["impl"], "limit": 500})["events"]
    assert only_impl and all(event.get("task_id") == ids["impl"] for event in only_impl)

    counts = _result("org.events", {"limit": 500})["counts_by_type"]
    assert sum(counts.values()) >= len(only_impl)


def test_audit_is_the_executive_view_over_the_real_graph(org):
    ids = _plan(org)
    result = _result("org.audit")
    OrgAuditResult.model_validate(result)
    blob = json.dumps(result["audit"], default=str)
    assert ids["impl"] in blob
    assert result["render"], "Boss Audit Mode renders as text for dense surfaces"

    _run_to_running(org, ids["impl"], "coding")
    org.runtime.tasks.complete(
        ids["impl"], summary="export works", outputs=[{"kind": "summary", "text": "export works"}]
    )
    with_outputs = _result("org.audit", {"include_outputs": True})["audit"]
    without = _result("org.audit", {"include_outputs": False})["audit"]
    assert "export works" in json.dumps(with_outputs, default=str)
    assert with_outputs != without, "include_outputs must actually change the report"


# ============================================================
# writes — real operator authority, not acknowledgements
# ============================================================


def test_approve_and_deny_move_real_tasks(org):
    ids = _plan(org)
    assert _result("org.approvals")["pending"] == []

    org.runtime.request_approval(ids["impl"], "Provide staging credentials?")
    pending = _result("org.approvals")["pending"]
    OrgApprovalsResult.model_validate(_result("org.approvals"))
    assert len(pending) == 1 and pending[0]["task_id"] == ids["impl"]
    assert org.runtime.tasks.get(ids["impl"]).status is TaskStatus.WAITING_APPROVAL

    approved = _result("org.approve", {
        "approval_id": pending[0]["id"], "decided_by": "operator", "note": "go ahead",
    })
    OrgApprovalResult.model_validate(approved)
    assert approved["approval"]["decision"] == "approved"
    assert _result("org.approvals")["pending"] == []
    assert org.runtime.tasks.get(ids["impl"]).status is not TaskStatus.WAITING_APPROVAL

    # Denial is not a shrug: the task is failed with the operator's reason recorded.
    org.runtime.request_approval(ids["test"], "Run the paid test suite?")
    denial_id = _result("org.approvals")["pending"][0]["id"]
    denied = _result("org.deny", {"approval_id": denial_id, "note": "not budgeted"})
    assert denied["approval"]["decision"] == "denied"
    assert org.runtime.tasks.get(ids["test"]).status is TaskStatus.FAILED
    assert org.runtime.tasks.get(ids["test"]).failure_reason == "approval_denied"


def test_approval_errors_are_typed(org):
    assert _envelope("org.approve", {})["error"]["code"] == 4000
    assert _envelope("org.deny", {"approval_id": "ap-nothing"})["error"]["code"] == 4004


def test_pause_resume_and_stop_reach_the_runtime(org):
    ids = _plan(org)

    paused = _result("org.pause", {"reason": "operator inspecting"})
    OrgPauseResult.model_validate(paused)
    assert paused["paused"] is True
    assert org.runtime.run.paused is True
    assert org.runtime.snapshot()["run"]["paused"] is True

    resumed = _result("org.resume")
    OrgPauseResult.model_validate(resumed)
    assert resumed["paused"] is False
    assert org.runtime.run.paused is False

    stopped = _result("org.stop", {"reason": "abandon the run"})
    OrgStopResult.model_validate(stopped)
    assert stopped["stopped"] is True
    assert set(stopped["cancelled"]) >= {ids["impl"], ids["test"], ids["docs"]}
    for key in ("impl", "test", "docs"):
        assert org.runtime.tasks.get(ids[key]).status is TaskStatus.CANCELLED


def test_task_control_performs_the_real_transition(org):
    ids = _plan(org)
    _run_to_running(org, ids["impl"], "coding")
    org.runtime.tasks.fail(ids["impl"], "the export crashed", error="ValueError")
    assert org.runtime.tasks.get(ids["impl"]).status is TaskStatus.FAILED

    retried = _result("org.task.control", {
        "task_id": ids["impl"], "op": "retry", "reason": "fixed the encoder",
    })
    OrgTaskControlResult.model_validate(retried)
    assert retried["op"] == "retry" and retried["task_id"] == ids["impl"]
    assert org.runtime.tasks.get(ids["impl"]).status is not TaskStatus.FAILED

    _result("org.task.control", {"task_id": ids["docs"], "op": "cancel", "reason": "out of scope"})
    assert org.runtime.tasks.get(ids["docs"]).status is TaskStatus.CANCELLED


def test_task_control_review_goes_through_the_boss(org):
    ids = _plan(org)
    _run_to_running(org, ids["impl"], "coding")
    org.runtime.tasks.request_review(ids["impl"])
    assert org.runtime.tasks.get(ids["impl"]).status is TaskStatus.IN_REVIEW

    result = _result("org.task.control", {
        "task_id": ids["impl"], "op": "review", "approved": True, "note": "verified",
    })
    assert result["result"]["ok"] is True
    assert org.runtime.tasks.get(ids["impl"]).status is TaskStatus.COMPLETED


def test_task_control_errors_are_typed(org):
    ids = _plan(org)
    assert _envelope("org.task.control", {})["error"]["code"] == 4000
    assert _envelope("org.task.control", {"task_id": "nope", "op": "retry"})["error"]["code"] == 4004

    unknown_op = _envelope("org.task.control", {"task_id": ids["impl"], "op": "sideways"})
    assert unknown_op["error"]["code"] == 4002
    assert set(unknown_op["error"]["data"]["valid"]) == {
        "retry", "cancel", "resolve_blocker", "review",
    }

    # `review` without a verdict is a caller bug, not a silent approval.
    assert _envelope(
        "org.task.control", {"task_id": ids["impl"], "op": "review"}
    )["error"]["code"] == 4002


def test_an_unavailable_runtime_is_an_error_not_fabricated_state(org, monkeypatch):
    """The documented fallback is a typed error — never a 'last known good' panel."""
    monkeypatch.setattr(methods_org, "_org_runtime", lambda: None, raising=False)
    monkeypatch.setattr(srv, "_org_runtime", lambda: None, raising=False)

    needs_runtime = (
        "org.status", "org.audit", "org.agents", "org.tasks", "org.events",
        "org.approvals", "org.approve", "org.deny", "org.pause", "org.resume",
        "org.stop", "org.task.control",
    )
    for name in needs_runtime:
        envelope = _envelope(name, {"task_id": "x", "op": "retry", "approval_id": "x"})
        assert "result" not in envelope, f"{name} invented a payload without a runtime"
        assert envelope["error"]["code"] == 5030, name

    # The roster is served from the role catalog, not the runtime, so it still answers.
    OrgRolesResult.model_validate(_result("org.roles"))
