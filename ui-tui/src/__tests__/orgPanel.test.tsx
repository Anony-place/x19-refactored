import React from 'react'
import { beforeEach, describe, expect, it } from 'vitest'

import { renderToScreen } from '../../packages/x19-ink/src/ink/render-to-screen.js'
import { cellAtIndex } from '../../packages/x19-ink/src/ink/screen.js'
import {
  $orgDockCollapsed,
  $orgEvents,
  appendOrgEvents,
  applyOrgAgents,
  applyOrgStatus,
  clearOrgState,
  getOrgStatus,
  orgHasRun
} from '../app/orgStore.js'
import { OrgPanelView } from '../components/orgPanel.js'
import { DEFAULT_THEME } from '../theme.js'

/**
 * The console must reflect *runtime* state, so these fixtures are real
 * `org.status` / `org.agents` / `org.events` payloads captured from the X19
 * organization runtime (not invented shapes): an objective accepted by the boss,
 * two steps planned by the manager, one of them waiting on a dependency.
 */
const STATUS = {
  status: {
    run: {
      run_id: 'x19-run-82450da624',
      objective: 'Deploy the monitoring stack',
      objective_task_id: 'x19-t-c2a170c1b1',
      project_task_id: 'x19-t-e0a218cb14',
      started_at: 1789800654.02,
      finished_at: null,
      elapsed_seconds: 72,
      phase: 'running',
      paused: false,
      stopped: false,
      active: true
    },
    phase: {
      label: 'ready',
      detail: '1 task(s) ready to dispatch; 1 still waiting on dependencies',
      steps_total: 2,
      steps_completed: 0,
      steps_running: 1,
      steps_waiting: 1,
      steps_failed: 0,
      steps_in_review: 0,
      steps_cancelled: 0,
      steps_queued: 1
    },
    counts: { total: 4, active: 2, waiting: 1, completed: 1, failed: 0, cancelled: 0, in_review: 0, queued: 1, retryable: 0 },
    overall_state: 'running',
    boss: { role_id: 'x19', state: 'active', run_active: true, paused: false },
    manager: {
      role_id: 'x22',
      state: 'active',
      current_task_id: 'x19-t-23ae1a85cb',
      current_objective: 'Deploy the monitoring stack',
      tasks_completed: 1,
      tasks_failed: 0,
      last_error: null
    },
    ready: [{ task_id: 'x19-t-15e86fdb79', objective: 'Compare uptime monitoring vendors', role_id: 'research', priority: 'normal' }],
    blocked: [],
    failed: [],
    in_review: [],
    pending_approvals: [],
    next_actions: [
      { kind: 'wait', task_id: 'x19-t-1611660351', detail: 'waiting on x19-t-15e86fdb79' },
      { kind: 'dispatch', task_id: 'x19-t-15e86fdb79', detail: 'dispatch research: Compare uptime monitoring vendors' }
    ],
    active_agents: [],
    recent_events: [],
    generated_at: 1789800726.1
  },
  render: 'X19 · Deploy the monitoring stack'
} as any

const AGENTS = {
  agents: [
    {
      agent_id: 'x19',
      role_id: 'x19',
      kind: 'boss',
      display_name: 'X19',
      title: 'Boss / Executive Orchestrator',
      state: 'active',
      manager_id: null,
      running_seconds: 72
    },
    { agent_id: 'x22', role_id: 'x22', kind: 'manager', display_name: 'X22', state: 'active', manager_id: 'x19', running_seconds: 70 },
    {
      agent_id: 'research-1',
      role_id: 'research',
      kind: 'worker',
      display_name: 'Research',
      state: 'active',
      manager_id: 'x22',
      current_objective: 'Compare uptime monitoring vendors',
      running_seconds: 41
    },
    { agent_id: 'coding-1', role_id: 'coding', kind: 'worker', display_name: 'Coding', state: 'idle', manager_id: 'x22' },
    { agent_id: 'testing-1', role_id: 'testing', kind: 'worker', display_name: 'Testing', state: 'idle', manager_id: 'x22' }
  ],
  live_subagents: [],
  counts: {}
} as any

const EVENTS = {
  events: [
    { seq: 1, ts: 1789800670.86, type: 'task.created', message: 'task created', task_id: 'x19-t-eecd', role_id: 'x19', agent_id: null },
    { seq: 2, ts: 1789800671.1, type: 'task.planned', message: 'task planned', task_id: 'x19-t-15e8', role_id: 'research', agent_id: null },
    { seq: 3, ts: 1789800672.4, type: 'agent.started', message: 'agent started', task_id: 'x19-t-15e8', role_id: 'research', agent_id: 'research-1' }
  ],
  last_seq: 3,
  counts_by_type: { 'task.created': 1, 'task.planned': 1, 'agent.started': 1 }
} as any

const text = (el: React.ReactElement, cols: number, height?: number) => {
  const view = renderToScreen(el, cols)
  const rows = height ?? view.height

  return Array.from({ length: rows }, (_, r) =>
    Array.from({ length: cols }, (_, c) => cellAtIndex(view.screen, r * cols + c).char).join('').trimEnd()
  ).join('\n')
}

const renderPanel = (cols = 96, height?: number) => {
  const status = getOrgStatus()!

  return text(<OrgPanelView cols={cols} status={status} t={DEFAULT_THEME} />, cols, height)
}

beforeEach(() => {
  clearOrgState()
  $orgDockCollapsed.set(false)
  applyOrgStatus(STATUS)
  applyOrgAgents(AGENTS)
  appendOrgEvents(EVENTS)
})

describe('org store', () => {
  it('adopts a real run and exposes it through the gate', () => {
    const status = getOrgStatus()

    expect(orgHasRun(status)).toBe(true)
    expect(status?.run?.run_id).toBe('x19-run-82450da624')
    expect(status?.run?.objective).toBe('Deploy the monitoring stack')
    expect(status?.counts?.total).toBe(4)
    expect(status?.manager?.role_id).toBe('x22')
  })

  it('renders nothing rather than an empty org chart when no run exists', () => {
    applyOrgStatus({ status: {} } as any)
    expect(orgHasRun(getOrgStatus())).toBe(false)
    expect(getOrgStatus()).toBeNull()

    applyOrgStatus(null)
    expect(getOrgStatus()).toBeNull()
  })

  it('never fabricates rows from a malformed or partial payload', () => {
    applyOrgStatus({ status: { run: { run_id: 'r' } } } as any)
    const status = getOrgStatus()

    expect(status?.run?.objective).toBe('')
    expect(status?.counts).toBeNull()
    expect(status?.boss).toBeNull()
    expect(status?.manager).toBeNull()
    expect(status?.ready).toEqual([])
    expect(status?.next_actions).toEqual([])
    expect(status?.overall_state).toBe('unknown')
  })

  it('merges events by seq so incremental polling cannot duplicate', () => {
    appendOrgEvents(EVENTS)
    appendOrgEvents({ events: EVENTS.events.slice(1), last_seq: 3 } as any)
    expect(getOrgStatus()).not.toBeNull()

    appendOrgEvents({ events: [{ seq: 4, ts: 1, type: 'task.completed', message: 'done' }], last_seq: 4 } as any)

    const seqs = $orgEvents.get().map(e => e.seq)

    expect(seqs).toEqual([1, 2, 3, 4])
  })
})

describe('org console', () => {
  it('shows the executive hierarchy distinctly: X19, X22 and the workers', () => {
    const out = renderPanel()

    expect(out).toContain('X19 · Deploy the monitoring stack')
    expect(out).toMatch(/boss\s+● X19 active/)
    expect(out).toMatch(/manager\s+● X22 active/)
    expect(out).toMatch(/workers\s+1 live · 3 registered/)
  })

  it('reports the task graph counts from runtime state', () => {
    const out = renderPanel()

    expect(out).toMatch(/tasks\s+total 4/)
    expect(out).toContain('queued 1')
    expect(out).toContain('running 1')
    expect(out).toContain('done 1')
  })

  it('names the live worker and what it is actually working on', () => {
    const out = renderPanel()

    expect(out).toContain('research')
    expect(out).toContain('Compare uptime monitoring vendors')
    expect(out).toContain('41s')
  })

  it('surfaces the runtime’s own derived next action', () => {
    const out = renderPanel()

    expect(out).toMatch(/next\s+wait: waiting on x19-t-15e86fdb79 · dispatch: dispatch research/)
  })

  it('never reports a task waiting on a dependency as blocked', () => {
    // `status.blocked` from the server is the union of BLOCKED,
    // WAITING_DEPENDENCY and WAITING_APPROVAL. Painting all three red as
    // "blocked" would misrepresent normal graph progress as a stall.
    applyOrgStatus({
      ...STATUS,
      status: {
        ...STATUS.status,
        counts: { ...STATUS.status.counts, waiting: 1 },
        blocked: [
          { task_id: 'x19-t-test', objective: 'Write and run tests for CSV export', role_id: 'testing', status: 'waiting_dependency' }
        ]
      }
    } as any)

    const status = getOrgStatus()!

    expect(status.waiting).toHaveLength(1)
    expect(status.blocked).toHaveLength(0)
    expect(status.awaitingApproval).toHaveLength(0)

    const out = renderPanel()

    expect(out).not.toContain('attention')
    expect(out).not.toContain('⊘')
    expect(out).toContain('waiting 1')
  })

  it('separates a real blockage from a task held for approval', () => {
    applyOrgStatus({
      ...STATUS,
      status: {
        ...STATUS.status,
        blocked: [
          { task_id: 'x19-t-a', objective: 'Harden the deploy pipeline', role_id: 'security', status: 'blocked', reason: 'no credentials' },
          { task_id: 'x19-t-b', objective: 'Run the paid test suite', role_id: 'testing', status: 'waiting_approval' }
        ]
      }
    } as any)

    const status = getOrgStatus()!

    expect(status.blocked.map(r => r.task_id)).toEqual(['x19-t-a'])
    expect(status.awaitingApproval.map(r => r.task_id)).toEqual(['x19-t-b'])
    expect(status.blocked[0]!.reason).toBe('no credentials')

    const out = renderPanel()

    expect(out).toContain('attention')
    expect(out).toContain('no credentials')
    expect(out).toContain('awaiting your decision')
  })

  it('counts a blocked task once, not as both waiting and blocked', () => {
    // The backend's `counts.waiting` is the union of BLOCKED,
    // WAITING_DEPENDENCY and WAITING_APPROVAL — the same set it returns as
    // `status.blocked`. Rendering that number beside a blocked count showed the
    // blocked task twice, so the summary slices must partition the union.
    applyOrgStatus({
      ...STATUS,
      status: {
        ...STATUS.status,
        counts: { ...STATUS.status.counts, total: 3, waiting: 3 },
        blocked: [
          { task_id: 'x19-t-a', objective: 'Harden the deploy pipeline', role_id: 'security', status: 'blocked', reason: 'no credentials' },
          { task_id: 'x19-t-b', objective: 'Write and run tests for CSV export', role_id: 'testing', status: 'waiting_dependency' },
          { task_id: 'x19-t-c', objective: 'Run the paid test suite', role_id: 'testing', status: 'waiting_approval' }
        ]
      }
    } as any)

    const status = getOrgStatus()!

    expect(status.blocked).toHaveLength(1)
    expect(status.waiting).toHaveLength(1)
    expect(status.awaitingApproval).toHaveLength(1)

    const out = renderPanel()

    // 3 tasks are held; exactly 1 of them is blocked.
    expect(out).toContain('waiting 2')
    expect(out).toContain('blocked 1')
    expect(out).not.toContain('waiting 3')
  })

  it('renders the real event stream with its own seq ordering', () => {
    const out = renderPanel()

    expect(out).toContain('events')
    expect(out).toContain('task.planned')
    expect(out).toContain('agent.started')
  })

  it('flags blocked tasks and pending approvals as attention', () => {
    applyOrgStatus({
      ...STATUS,
      status: {
        ...STATUS.status,
        overall_state: 'awaiting_operator',
        blocked: [{ task_id: 'x19-t-9', objective: 'Harden the deploy pipeline', role_id: 'security', priority: 'high' }],
        failed: [{ task_id: 'x19-t-8', objective: 'Test CSV export', role_id: 'testing', priority: 'normal' }],
        pending_approvals: [{ id: 'ap-1', task_id: 'x19-t-9', question: 'Approve production deploy?' }]
      }
    } as any)

    const out = renderPanel()

    expect(out).toContain('attention')
    expect(out).toContain('Approve production deploy?')
    expect(out).toContain('Harden the deploy pipeline')
    expect(out).toContain('Test CSV export')
  })

  it('stays inside the given width at every size', () => {
    for (const cols of [40, 58, 72, 96, 140]) {
      const view = renderToScreen(<OrgPanelView cols={cols} status={getOrgStatus()!} t={DEFAULT_THEME} />, cols)

      const rows = Array.from({ length: view.height }, (_, r) =>
        Array.from({ length: cols }, (_, c) => cellAtIndex(view.screen, r * cols + c).char).join('')
      )

      expect(rows.every(row => row.length <= cols)).toBe(true)
      expect(view.height).toBeGreaterThan(3)
    }
  })

  it('collapses to a compact summary that still carries the counts', () => {
    $orgDockCollapsed.set(true)
    const view = renderToScreen(<OrgPanelView cols={96} status={getOrgStatus()!} t={DEFAULT_THEME} />, 96)

    expect(view.height).toBe(2)

    const out = renderPanel(96, 2)

    expect(out).toContain('X19 · Deploy the monitoring stack')
    expect(out).toContain('total 4')
    expect(out).toContain('Ctrl+G expand')
  })

  it('drops low-priority sections on a narrow terminal but keeps the hierarchy', () => {
    const out = renderPanel(44)

    expect(out).toContain('boss')
    expect(out).toContain('manager')
    expect(out).toContain('workers')
    expect(out).toContain('tasks')
    // events and next actions are width-gated out below 62 columns
    expect(out).not.toContain('events')
    expect(out).not.toContain('next')
  })
})
