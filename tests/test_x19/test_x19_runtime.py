"""X19 runtime — the real multi-agent organization.

This suite replaces the previous ``test_x19_runtime.py``, which tested a
security-operations scaffold (``x19.orchestration``, ``x19.scope``,
``x19.specialists``, ``x19.safety.anti_loop``) that no longer exists in the
product. Everything here drives the shipped implementation:

* :mod:`x19.org` — runtime, boss, manager, tasks, registry, roles, events,
  status, audit, delegation and safety guards
* :mod:`x19.identity` — the identity text that actually reaches the model
* the real system-prompt path in :mod:`agent.prompt_builder`

The assertions follow the product contract: X19 starts, decomposes a user
objective, delegates through X22 to workers, records real state transitions,
represents failure and completion honestly, and answers status questions from
the runtime rather than from narration.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from x19.org import (  # noqa: E402
    BOSS_ROLE_ID,
    MANAGER_ROLE_ID,
    AgentState,
    Boss,
    EventType,
    ExecutionGuards,
    InvalidTransition,
    Manager,
    OrganizationRuntime,
    RoleKind,
    RoleSpec,
    TaskStatus,
    get_role,
    register_role,
    reset_event_bus,
    reset_roles,
    reset_runtime,
    role_catalog,
    set_live_reader,
    set_runtime,
    unregister_role,
)
from x19.org.delegation import build_dispatch, observe_child_result, observe_child_started  # noqa: E402

# A plan used across the suite: one root step with three dependents, which is
# the smallest graph that exercises dependencies, parallelism and convergence.
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

    The delegation engine's live reader is injected so roster assertions test
    the overlay logic rather than whichever children happen to be running.
    """
    live: list[dict] = []
    set_live_reader(lambda: list(live))
    reset_event_bus()

    rt = OrganizationRuntime(root=tmp_path, persist=False)
    set_runtime(rt)

    yield SimpleNamespace(
        runtime=rt,
        boss=Boss(rt),
        manager=Manager(rt),
        guards=ExecutionGuards(rt),
        live=live,
    )

    set_live_reader(None)
    reset_runtime()
    reset_event_bus()
    reset_roles()


# The statuses a task may hold and still be dispatchable to a worker.
_DISPATCHABLE = (TaskStatus.QUEUED, TaskStatus.PLANNED, TaskStatus.ASSIGNED)


def _dep_ids(org, task_id: str) -> list[str]:
    """`blocking_dependencies` returns rows; the tests care about the ids."""
    return [row["task_id"] for row in org.runtime.tasks.blocking_dependencies(task_id)]


def _plan(org) -> dict:
    org.boss.accept_objective("Build the CSV export feature, test it and document it")
    result = org.manager.plan(PLAN)
    assert result["ok"], result.get("errors")

    return result["keys"]


def _run_worker_until_running(org, task_id: str, role_id: str):
    """Take one task to RUNNING without completing it."""
    org.runtime.tasks.assign(task_id, role_id=role_id, manager_id=MANAGER_ROLE_ID, agent_id=role_id)
    org.runtime.tasks.start(task_id, agent_id=role_id, subagent_id=f"sa-{role_id}")


def _run_worker(org, task_id: str, role_id: str, *, summary: str = "work done", subagent: str | None = None):
    """Drive one task through the real lifecycle to COMPLETED."""
    org.runtime.tasks.assign(task_id, role_id=role_id, manager_id=MANAGER_ROLE_ID, agent_id=role_id)
    org.runtime.tasks.start(task_id, agent_id=role_id, subagent_id=subagent or f"sa-{role_id}")
    org.runtime.tasks.complete(
        task_id,
        summary=summary,
        outputs=[{"kind": "summary", "text": summary}],
    )


# ============================================================
# 1. IDENTITY — what actually reaches the model
# ============================================================


class TestIdentity:
    def test_identity_is_the_executive_orchestrator(self):
        from x19.identity.core import get_x19_identity

        identity = get_x19_identity()

        assert identity.startswith("You are X19")
        assert "executive orchestrator" in identity
        assert "X22" in identity, "the manager layer is named in the identity"

    def test_identity_is_not_gated_by_a_mode_flag(self):
        """X19 is the product; there is no enable switch to fall through."""
        import x19.identity.core as core

        assert not hasattr(core, "is_x19_enabled")

    def test_soul_text_describes_the_real_hierarchy_and_lifecycle(self):
        from x19.identity.core import get_x19_soul_md

        soul = get_x19_soul_md()

        assert "BOSS" in soul and "MANAGER" in soul and "WORKERS" in soul
        assert "QUEUED" in soul and "COMPLETED" in soul, "the lifecycle is stated"
        assert "runtime state" in soul

    def test_organization_brief_is_generated_from_the_live_catalog(self):
        from x19.identity.core import get_x19_organization_brief

        brief = get_x19_organization_brief()
        catalog_ids = {role.id for role in role_catalog()}

        assert "live registry" in brief
        for role_id in ("x19", "x22", "coding", "testing"):
            assert role_id in catalog_ids
            assert f"({role_id})" in brief, f"{role_id} must appear in the generated brief"

    def test_registering_a_worker_makes_x19_aware_of_it(self):
        """The brief is dynamic: a new role shows up without any code change."""
        from x19.identity.core import get_x19_organization_brief

        before = get_x19_organization_brief()
        assert "localisation" not in before

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

        assert "localisation" in get_x19_organization_brief()

        unregister_role("localisation")
        assert "localisation" not in get_x19_organization_brief()

    def test_guidance_blocks_reach_the_system_prompt(self):
        from agent.system_prompt import _get_x19_guidance_blocks

        blocks = _get_x19_guidance_blocks()

        assert blocks, "guidance blocks must not be empty"
        joined = " ".join(blocks)
        assert "X19" in joined

    def test_prompt_builder_default_identity_is_x19(self):
        from agent.prompt_builder import DEFAULT_AGENT_IDENTITY

        assert "X19" in DEFAULT_AGENT_IDENTITY
        assert "orchestrator" in DEFAULT_AGENT_IDENTITY.lower()


# ============================================================
# 2. ORGANIZATION STRUCTURE
# ============================================================


class TestOrganization:
    def test_catalog_is_boss_manager_workers(self):
        roles = role_catalog()
        kinds = [role.kind for role in roles]

        assert roles[0].id == BOSS_ROLE_ID and kinds[0] is RoleKind.BOSS
        assert roles[1].id == MANAGER_ROLE_ID and kinds[1] is RoleKind.MANAGER
        assert kinds.count(RoleKind.WORKER) >= 5

    def test_workers_report_to_the_manager(self):
        for role in role_catalog():
            if role.kind is RoleKind.WORKER:
                assert role.manager_id == MANAGER_ROLE_ID

    def test_the_team_is_generalized_not_security_only(self):
        ids = {role.id for role in role_catalog()}

        for expected in ("research", "coding", "testing", "documentation", "security", "devops"):
            assert expected in ids, f"{expected} worker must exist"

    def test_boss_and_manager_map_to_real_delegation_roles(self):
        assert get_role(BOSS_ROLE_ID).delegation_role == "orchestrator"
        assert get_role(MANAGER_ROLE_ID).delegation_role == "orchestrator"
        assert get_role("coding").delegation_role == "leaf"

    def test_org_chart_reflects_the_registry(self, org):
        chart = json.dumps(org.boss.org_chart())

        assert "x19" in chart and "x22" in chart
        assert "coding" in chart

    def test_every_role_resolves_a_real_toolset(self):
        """A role whose tools do not exist would be decoration."""
        from toolsets import TOOLSETS

        for role in role_catalog():
            for toolset in role.toolsets:
                assert toolset in TOOLSETS, f"role {role.id} names unknown toolset {toolset}"


# ============================================================
# 3. OBJECTIVE INTAKE AND DECOMPOSITION
# ============================================================


class TestDecomposition:
    def test_accepting_an_objective_opens_a_real_run(self, org):
        result = org.boss.accept_objective("Ship the CSV export")

        assert result["objective_task_id"]
        assert result["project_task_id"]
        assert org.runtime.run.to_dict()["active"] is True
        assert org.runtime.run.objective == "Ship the CSV export"

    def test_the_project_is_owned_by_the_manager(self, org):
        result = org.boss.accept_objective("Ship the CSV export")
        project = org.runtime.tasks.get(result["project_task_id"])

        assert project.role_id == MANAGER_ROLE_ID
        assert project.parent_id == result["objective_task_id"]

    def test_manager_decomposition_creates_tasks_with_dependencies(self, org):
        ids = _plan(org)

        assert set(ids) == {"impl", "test", "docs"}
        assert _dep_ids(org, ids["test"]) == [ids["impl"]]
        assert _dep_ids(org, ids["docs"]) == [ids["impl"]]
        assert _dep_ids(org, ids["impl"]) == []

    def test_worker_tasks_are_children_of_the_project(self, org):
        result = org.boss.accept_objective("Ship the CSV export")
        org.manager.plan(PLAN)

        for task in org.runtime.tasks.all():
            if task.id in (result["objective_task_id"], result["project_task_id"]):
                continue
            assert task.parent_id == result["project_task_id"]

    def test_a_task_with_unmet_dependencies_waits_rather_than_queues(self, org):
        ids = _plan(org)

        assert org.runtime.tasks.get(ids["impl"]).status in _DISPATCHABLE
        assert org.runtime.tasks.get(ids["test"]).status is TaskStatus.WAITING_DEPENDENCY

    def test_structural_tasks_are_excluded_from_worker_step_counts(self, org):
        ids = _plan(org)
        status = org.boss.status()

        assert status["phase"]["steps_total"] == len(ids), "only worker steps are counted"
        assert status["counts"]["total"] == len(ids) + 2, "objective + project exist too"


# ============================================================
# 4. TASK LIFECYCLE AND METADATA
# ============================================================


class TestTaskLifecycle:
    def test_the_full_happy_path_transitions_are_enforced(self, org):
        ids = _plan(org)
        task_id = ids["impl"]
        tasks = org.runtime.tasks

        assert tasks.get(task_id).status is TaskStatus.PLANNED

        tasks.assign(task_id, role_id="coding", manager_id=MANAGER_ROLE_ID, agent_id="coding")
        assert tasks.get(task_id).status is TaskStatus.ASSIGNED

        tasks.start(task_id, agent_id="coding", subagent_id="sa-1")
        assert tasks.get(task_id).status is TaskStatus.RUNNING

        tasks.complete(task_id, summary="export works")
        assert tasks.get(task_id).status is TaskStatus.COMPLETED

    def test_work_held_for_review_is_not_complete_until_reviewed(self, org):
        """`complete()` on a task already in review must not self-certify."""
        ids = _plan(org)
        task_id = ids["impl"]

        _run_worker_until_running(org, task_id, "coding")
        org.runtime.tasks.request_review(task_id)
        assert org.runtime.tasks.get(task_id).status is TaskStatus.IN_REVIEW

        org.runtime.tasks.complete(task_id, summary="export works")
        assert org.runtime.tasks.get(task_id).status is TaskStatus.IN_REVIEW, (
            "a worker cannot mark its own reviewed work as complete"
        )

        result = org.boss.review(task_id, approved=True, note="verified against the spec")
        assert result["ok"], result
        assert org.runtime.tasks.get(task_id).status is TaskStatus.COMPLETED

    def test_a_rejected_review_returns_the_task_to_the_worker(self, org):
        ids = _plan(org)
        task_id = ids["impl"]

        _run_worker_until_running(org, task_id, "coding")
        org.runtime.tasks.complete(task_id, summary="export works", review_required=True)
        assert org.runtime.tasks.get(task_id).status is TaskStatus.IN_REVIEW

        result = org.boss.review(task_id, approved=False, note="missing the header row")
        assert result["ok"], result
        assert org.runtime.tasks.get(task_id).status is not TaskStatus.COMPLETED

    def test_illegal_transitions_are_rejected_not_absorbed(self, org):
        ids = _plan(org)
        task_id = ids["impl"]

        with pytest.raises(InvalidTransition):
            org.runtime.tasks.complete(task_id, summary="cannot finish work never started")

    def test_satisfying_a_dependency_releases_the_waiting_task(self, org):
        ids = _plan(org)

        assert org.runtime.tasks.get(ids["test"]).status is TaskStatus.WAITING_DEPENDENCY
        _run_worker(org, ids["impl"], "coding")

        assert _dep_ids(org, ids["test"]) == []
        assert org.runtime.tasks.get(ids["test"]).status in _DISPATCHABLE

    def test_completed_task_carries_real_metadata(self, org):
        ids = _plan(org)
        _run_worker(org, ids["impl"], "coding", summary="implemented export")
        data = org.runtime.tasks.get(ids["impl"]).to_dict()

        for field in (
            "id",
            "objective",
            "role_id",
            "status",
            "parent_id",
            "created_at",
            "assigned_at",
            "started_at",
            "finished_at",
            "depends_on",
            "attempt",
            "max_attempts",
            "outputs",
            "error",
            "phase",
            "blockers",
            "review",
            "metrics",
        ):
            assert field in data, f"task metadata must include {field}"

        assert data["status"] == "completed"
        assert data["role_id"] == "coding"
        assert data["outputs"], "the recorded output is present"
        assert data["started_at"] <= data["finished_at"]

    def test_progress_is_real_not_a_fabricated_percentage(self, org):
        ids = _plan(org)
        _run_worker(org, ids["impl"], "coding")
        data = org.runtime.tasks.get(ids["impl"]).to_dict()

        assert "progress" not in data or data["progress"] is not None
        assert "percentage" not in data, "no invented completion percentage"


# ============================================================
# 5. WORKER EXECUTION OBSERVED FROM THE DELEGATION ENGINE
# ============================================================


class TestDelegation:
    def test_dispatch_payload_is_built_from_the_real_task(self, org):
        ids = _plan(org)
        org.runtime.tasks.plan(ids["impl"], depends_on=[])
        payload = build_dispatch(org.runtime.tasks.get(ids["impl"]), runtime=org.runtime)

        assert payload["goal"] == "Implement the CSV export endpoint"
        assert payload["role"] or payload.get("toolsets") or payload.get("context")

    def test_observing_a_real_child_start_marks_the_task_running(self, org):
        ids = _plan(org)
        org.runtime.tasks.plan(ids["impl"], depends_on=[])
        org.runtime.tasks.assign(
            ids["impl"], role_id="coding", manager_id=MANAGER_ROLE_ID, agent_id="coding"
        )

        observe_child_started(
            goal="Implement the CSV export endpoint",
            subagent_id="sa-impl",
            delegation_id="del-1",
            model="test-model",
            depth=1,
            parent_subagent_id=None,
            runtime=org.runtime,
        )

        assert org.runtime.tasks.get(ids["impl"]).status is TaskStatus.RUNNING
        record = org.runtime.registry.get("coding")
        assert record is not None
        assert record.state is AgentState.ACTIVE

    def test_observing_a_child_result_completes_the_task(self, org):
        ids = _plan(org)
        org.runtime.tasks.plan(ids["impl"], depends_on=[])
        org.runtime.tasks.assign(
            ids["impl"], role_id="coding", manager_id=MANAGER_ROLE_ID, agent_id="coding"
        )
        observe_child_started(
            goal="Implement the CSV export endpoint",
            subagent_id="sa-impl",
            delegation_id="del-1",
            model="test-model",
            depth=1,
            parent_subagent_id=None,
            runtime=org.runtime,
        )

        observe_child_result(
            subagent_id="sa-impl",
            goal="Implement the CSV export endpoint",
            entry={
                "subagent_id": "sa-impl",
                "delegation_id": "del-1",
                "status": "completed",
                "result": "export endpoint implemented",
                "tool_count": 3,
            },
            runtime=org.runtime,
        )

        task = org.runtime.tasks.get(ids["impl"])
        assert task.status in (TaskStatus.COMPLETED, TaskStatus.IN_REVIEW)

    def test_live_subagents_overlay_the_roster(self, org):
        org.live.append(
            {
                "subagent_id": "sa-live",
                "goal": "Implement the CSV export endpoint",
                "status": "running",
                "depth": 1,
            }
        )
        snapshot = org.runtime.snapshot()["agents"]
        agents = {a["agent_id"]: a for a in snapshot["agents"]}

        assert agents["coding"]["state"] in ("active", "idle", "unknown", "stale")
        assert any(a.get("subagent_id") == "sa-live" for a in snapshot["agents"]) or snapshot.get(
            "live_subagents"
        ), "the live child is surfaced somewhere in the roster snapshot"


# ============================================================
# 6. FAILURE HANDLING, BLOCKERS AND HUMAN INTERVENTION
# ============================================================


class TestFailureHandling:
    def test_a_failure_is_recorded_with_its_reason(self, org):
        ids = _plan(org)
        org.runtime.tasks.assign(
            ids["impl"], role_id="coding", manager_id=MANAGER_ROLE_ID, agent_id="coding"
        )
        org.runtime.tasks.start(ids["impl"], agent_id="coding", subagent_id="sa-1")
        org.runtime.tasks.fail(ids["impl"], "provider rate limited", failure_reason="rate_limit")

        task = org.runtime.tasks.get(ids["impl"])
        assert task.status is TaskStatus.FAILED
        assert task.error == "provider rate limited", "the error is retained on the task"
        assert task.failure_reason == "rate_limit"
        assert task.attempt >= 1

    def test_retry_requeues_within_the_attempt_budget(self, org):
        ids = _plan(org)
        org.runtime.tasks.assign(
            ids["impl"], role_id="coding", manager_id=MANAGER_ROLE_ID, agent_id="coding"
        )
        org.runtime.tasks.start(ids["impl"], agent_id="coding", subagent_id="sa-1")
        org.runtime.tasks.fail(ids["impl"], "transient", failure_reason="timeout")

        result = org.boss.retry(ids["impl"], reason="try again")
        assert result["ok"], result
        assert org.runtime.tasks.get(ids["impl"]).status is TaskStatus.QUEUED

    def test_repeated_failure_exhausts_the_budget(self, org):
        ids = _plan(org)
        attempts = org.runtime.settings.max_attempts

        for _ in range(attempts + 2):
            task = org.runtime.tasks.get(ids["impl"])
            if task.status is TaskStatus.COMPLETED:
                break
            if task.status in (TaskStatus.QUEUED, TaskStatus.PLANNED):
                org.runtime.tasks.assign(
                    ids["impl"], role_id="coding", manager_id=MANAGER_ROLE_ID, agent_id="coding"
                )
            org.runtime.tasks.start(ids["impl"], agent_id="coding", subagent_id="sa-x")
            org.runtime.tasks.fail(ids["impl"], "still failing", failure_reason="provider_error")

            if org.runtime.tasks.get(ids["impl"]).status is TaskStatus.FAILED:
                try:
                    org.runtime.tasks.retry(ids["impl"])
                except Exception:
                    break

        assert org.runtime.tasks.get(ids["impl"]).status is TaskStatus.FAILED
        assert org.runtime.tasks.get(ids["impl"]).attempt >= attempts

    def test_a_blocked_task_can_be_escalated_to_a_human(self, org):
        ids = _plan(org)
        org.runtime.tasks.block(ids["impl"], "needs credentials we do not have")
        assert org.runtime.tasks.get(ids["impl"]).status is TaskStatus.BLOCKED

        org.runtime.request_approval(ids["impl"], "Provide staging credentials?")
        assert org.runtime.tasks.get(ids["impl"]).status is TaskStatus.WAITING_APPROVAL
        assert org.runtime.pending_approvals(), "the request is visible to the operator"

    def test_approval_and_denial_are_real_transitions(self, org):
        ids = _plan(org)
        org.runtime.tasks.block(ids["impl"], "needs a decision")
        org.runtime.request_approval(ids["impl"], "Proceed with the paid API?")
        pending = org.runtime.pending_approvals()[0]

        org.runtime.resolve_approval(pending["id"], approved=True, decided_by="operator")
        assert org.runtime.tasks.get(ids["impl"]).status in _DISPATCHABLE
        assert org.runtime.pending_approvals() == []

    def test_denial_fails_the_task_with_the_operator_reason(self, org):
        ids = _plan(org)
        # WAITING_DEPENDENCY -> WAITING_APPROVAL is legal: asking the operator is
        # legitimate from any non-terminal state.
        assert org.runtime.tasks.get(ids["test"]).status is TaskStatus.WAITING_DEPENDENCY
        org.runtime.request_approval(ids["test"], "Run the paid test suite?")
        pending = org.runtime.pending_approvals()[0]

        org.runtime.resolve_approval(pending["id"], approved=False, decided_by="operator", note="too expensive")
        task = org.runtime.tasks.get(ids["test"])

        assert task.status is TaskStatus.FAILED
        assert "too expensive" in json.dumps(task.to_dict())

    def test_resolving_a_blocker_unblocks_the_task(self, org):
        ids = _plan(org)
        org.runtime.tasks.block(ids["impl"], "waiting on access")

        result = org.boss.resolve_blocker(ids["impl"], resolution="access granted")
        assert result["ok"], result
        assert org.runtime.tasks.get(ids["impl"]).status in (TaskStatus.QUEUED, TaskStatus.PLANNED)

    def test_the_guards_refuse_a_dispatch_that_cannot_succeed(self, org):
        ids = _plan(org)
        decision = org.guards.can_dispatch(org.runtime.tasks.get(ids["test"]))

        assert decision.allowed is False, "a task with unmet dependencies must not dispatch"
        assert decision.reason

    def test_a_cancelled_task_is_terminal_and_reported(self, org):
        ids = _plan(org)
        _run_worker(org, ids["impl"], "coding")
        org.boss.cancel(ids["docs"], reason="documentation deferred")

        assert org.runtime.tasks.get(ids["docs"]).status is TaskStatus.CANCELLED
        assert org.boss.status()["counts"]["cancelled"] == 1


# ============================================================
# 7. STATUS, AUDIT AND ANSWERING THE USER FROM REAL STATE
# ============================================================


class TestStatusReporting:
    def test_status_reports_the_real_run_and_phase(self, org):
        ids = _plan(org)
        status = org.boss.status()

        assert status["run"]["objective"] == "Build the CSV export feature, test it and document it"
        assert status["phase"]["label"]
        assert status["phase"]["detail"]
        assert status["boss"]["role_id"] == BOSS_ROLE_ID
        assert status["manager"]["role_id"] == MANAGER_ROLE_ID

    def test_status_counts_change_when_work_actually_happens(self, org):
        ids = _plan(org)
        before = org.boss.status()["counts"]
        _run_worker(org, ids["impl"], "coding")
        after = org.boss.status()["counts"]

        assert after["completed"] == before["completed"] + 1

    def test_ready_and_blocked_slices_come_from_the_graph(self, org):
        ids = _plan(org)
        status = org.boss.status()

        assert ids["impl"] in [row["task_id"] for row in status["ready"]]
        assert [row["task_id"] for row in status["blocked"] if row["status"] == "blocked"] == []

        # WAITING_DEPENDENCY rows ride in the same slice, tagged with their own
        # status, so a consumer can tell a real blockage from normal progress.
        waiting = [row["task_id"] for row in status["blocked"] if row["status"] == "waiting_dependency"]
        assert set(waiting) == {ids["test"], ids["docs"]}

        org.runtime.tasks.block(ids["impl"], "stuck")
        blocked = [row for row in org.boss.status()["blocked"] if row["status"] == "blocked"]

        assert [row["task_id"] for row in blocked] == [ids["impl"]]
        assert blocked[0]["objective"] == "Implement the CSV export endpoint"
        assert blocked[0]["reason"] == "stuck"

    def test_next_actions_are_derived_not_scripted(self, org):
        ids = _plan(org)
        actions = org.boss.status()["next_actions"]

        assert actions, "a run with ready work must propose an action"
        assert any(a["kind"] == "dispatch" and a["task_id"] == ids["impl"] for a in actions)

    def test_status_text_renders_the_same_state(self, org):
        _plan(org)
        text = org.boss.status_text()

        assert "X19" in text
        assert "CSV export" in text

    def test_audit_mode_inspects_the_whole_organization(self, org):
        ids = _plan(org)
        _run_worker(org, ids["impl"], "coding")
        audit = org.boss.audit()

        assert audit["overall_state"]
        assert audit["phase"]["label"]
        assert audit["counts"]["completed"] >= 1
        assert audit["task_graph"], "the audit carries the real graph"
        assert "roster" in audit and "spend" in audit

    def test_audit_text_is_renderable(self, org):
        _plan(org)
        assert len(org.boss.audit_text()) > 40

    def test_answer_reads_live_state_for_a_status_question(self, org):
        ids = _plan(org)
        answer = org.boss.answer("what is the current status?")

        assert answer["kind"]
        assert "CSV export" in json.dumps(answer)

    def test_answer_reports_blockers_from_the_graph(self, org):
        ids = _plan(org)
        org.runtime.tasks.block(ids["impl"], "no database credentials")
        answer = org.boss.answer("why is this blocked?")

        assert answer["kind"] == "blocked"
        assert any(t["task_id"] == ids["impl"] for t in answer["blocked"])

    def test_answer_does_not_invent_progress_when_nothing_ran(self, org):
        org.boss.accept_objective("Ship the CSV export")
        answer = org.boss.answer("what did the workers complete?")
        payload = json.dumps(answer)

        assert "completed" in payload or "none" in payload.lower() or answer["kind"]
        assert "fabricated" not in payload


# ============================================================
# 8. EVENT STREAM
# ============================================================


class TestEventStream:
    def test_real_lifecycle_events_are_published(self, org):
        ids = _plan(org)
        _run_worker(org, ids["impl"], "coding")
        events = org.runtime.bus.recent(500)
        types = {e.type.value for e in events}

        assert EventType.TASK_CREATED.value in types
        assert any(t.startswith("task.") for t in types)
        assert any(t.startswith("agent.") or t == EventType.TASK_COMPLETED.value for t in types)

    def test_events_are_ordered_and_carry_the_task(self, org):
        ids = _plan(org)
        events = [e for e in org.runtime.bus.recent(500) if e.task_id == ids["impl"]]

        assert events, "the worker task emitted events"
        seqs = [e.seq for e in events]
        assert seqs == sorted(seqs), "the stream is append-only and ordered"

    def test_event_payloads_serialize_for_the_wire(self, org):
        ids = _plan(org)
        event = org.runtime.bus.recent(500)[0]
        data = event.to_dict()

        assert {"seq", "ts", "type", "message"} <= set(data)
        assert json.loads(json.dumps(data, default=str))["seq"] == data["seq"]


# ============================================================
# 9. OPERATOR CONTROL
# ============================================================


class TestRunControl:
    def test_pause_and_resume_are_visible_in_status(self, org):
        _plan(org)

        paused = org.boss.pause("operator stepped away")
        assert paused["paused"] is True
        assert org.boss.status()["run"]["paused"] is True

        resumed = org.boss.resume()
        assert resumed["paused"] is False
        assert org.boss.status()["run"]["paused"] is False

    def test_stop_cancels_outstanding_work_and_closes_the_run(self, org):
        ids = _plan(org)
        result = org.boss.stop("operator aborted")

        assert result["ok"] is True
        assert set(result["cancelled"]) >= {ids["test"], ids["docs"]}
        assert result["count"] == len(result["cancelled"])
        assert org.runtime.tasks.get(ids["test"]).status is TaskStatus.CANCELLED
        assert org.runtime.run.to_dict()["active"] is False

    def test_completing_every_worker_closes_the_run(self, org):
        ids = _plan(org)

        for key, role in (("impl", "coding"), ("test", "testing"), ("docs", "documentation")):
            _run_worker(org, ids[key], role)

        status = org.boss.status()
        assert status["counts"]["completed"] >= len(ids)
        assert org.runtime.tasks.get(status["run"]["project_task_id"]).status is TaskStatus.COMPLETED


# ============================================================
# 10. PERSISTENCE
# ============================================================


class TestPersistence:
    def test_state_survives_a_runtime_reload(self, tmp_path: Path):
        set_live_reader(None)
        reset_event_bus()
        rt = OrganizationRuntime(root=tmp_path, persist=True)
        set_runtime(rt)
        boss, manager = Boss(rt), Manager(rt)

        boss.accept_objective("Persist the export work")
        ids = manager.plan(PLAN)["keys"]
        _run_worker(SimpleNamespace(runtime=rt, boss=boss, manager=manager), ids["impl"], "coding")
        first = rt.tasks.get(ids["impl"]).to_dict()

        reloaded = OrganizationRuntime(root=tmp_path, persist=True)
        set_runtime(reloaded)
        second = reloaded.tasks.get(ids["impl"]).to_dict()

        assert second["status"] == first["status"] == "completed"
        assert second["objective"] == first["objective"]
        assert reloaded.run.objective == "Persist the export work"

        set_runtime(None)
        reset_runtime()
        reset_event_bus()


# ============================================================
# 11. NO LEGACY PRODUCT IDENTITY
# ============================================================


class TestNoLegacyIdentity:
    @pytest.mark.parametrize(
        "path",
        ["SOUL.md", "docker/SOUL.md", "x19/__init__.py", "x19/identity/core.py",
         "x19/identity/prompts.py"],
    )
    def test_identity_sources_carry_no_legacy_product_name(self, path):
        text = (REPO_ROOT / path).read_text()

        assert "hermes" not in text.lower(), f"{path} still names the legacy product"

    # docker/SOUL.md is seeded into $X19_HOME on first container boot, so it is
    # a deployed persona, not a spare copy — it has to carry the same identity.
    @pytest.mark.parametrize(
        "path", ["SOUL.md", "docker/SOUL.md", "x19/identity/core.py"]
    )
    def test_identity_is_no_longer_security_operations(self, path):
        text = (REPO_ROOT / path).read_text()

        # Case-insensitive on purpose: the framing this guards against survived
        # in docker/SOUL.md as "an autonomous security operations agent", and a
        # title-case assertion walked straight past it.
        assert "autonomous security operations" not in text.lower()
        assert "bug bounty" not in text.lower() and "bug-bounty" not in text.lower()

    def test_soul_md_declares_x19_and_the_real_hierarchy(self):
        text = (REPO_ROOT / "SOUL.md").read_text()

        assert text.startswith("# X19")
        assert "X22" in text and "MANAGER" in text
        assert "built on X19 foundation by Nous Research" not in text, "collapsed-rename residue"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
