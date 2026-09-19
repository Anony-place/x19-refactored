import type {
  OrgAgent,
  OrgAgentsResult,
  OrgEventsResult,
  OrgStatusResult
} from '@x19/shared/gateway-contract'
import { atom } from 'nanostores'
import { useCallback, useEffect, useRef } from 'react'

import type { GatewayRpc } from './interfaces.js'

/**
 * X19 organization state for the terminal console.
 *
 * Everything here is *server-owned*: this store is a cache of the `org.*` RPC
 * surface and never synthesizes a run, an agent or an event. When the gateway
 * reports no run, {@link orgHasRun} is false and the console renders nothing
 * rather than an empty org chart. The hierarchy, task graph and role catalog
 * are all discovered dynamically, so the UI cannot drift from the runtime.
 *
 * The wire rows are `OpenModel` (`Record<string, unknown>`) because their
 * closed field set is owned by `x19.org`, not by the gateway contract. The
 * narrow views below are the *only* place that coercion happens, and every
 * field is read defensively: a newer or older daemon must degrade a panel to
 * blank, never crash the render loop.
 */

export const ORG_POLL_MS = 2_000
export const ORG_EVENT_LIMIT = 200

// ── Narrow views over the server-owned rows ──────────────────────────

export interface OrgRun {
  run_id: string
  objective: string
  elapsed_seconds: number
  phase: string
  paused: boolean
  stopped: boolean
  active: boolean
}

export interface OrgPhase {
  label: string
  detail: string
  steps_total: number
  steps_completed: number
  steps_running: number
  steps_waiting: number
  steps_failed: number
  steps_in_review: number
  steps_queued: number
}

export interface OrgCounts {
  total: number
  active: number
  waiting: number
  completed: number
  failed: number
  cancelled: number
  in_review: number
  queued: number
}

/** A task summary row from `status.ready` / `.blocked` / `.failed`. */
export interface OrgTaskRow {
  task_id: string
  objective: string
  role_id: string | null
  priority: string | null
  /** The row's own lifecycle status. `status.blocked` mixes three states, so a
   *  consumer must never treat every row in it as blocked. */
  status: string | null
  reason: string | null
}

export interface OrgNextAction {
  kind: string
  task_id: string | null
  detail: string
}

export interface OrgBossRow {
  role_id: string
  state: string
  run_active: boolean
  paused: boolean
}

export interface OrgManagerRow {
  role_id: string
  state: string
  current_task_id: string | null
  current_objective: string | null
  tasks_completed: number
  tasks_failed: number
  last_error: string | null
}

/** One event from the append-only stream (`x19.org.events.OrgEvent`). */
export interface OrgEventRow {
  seq: number
  ts: number
  type: string
  message: string
  task_id: string | null
  role_id: string | null
  agent_id: string | null
}

export interface OrgApprovalRow {
  id: string
  task_id: string | null
  question: string
}

export interface OrgStatusView {
  run: OrgRun | null
  phase: OrgPhase | null
  counts: OrgCounts | null
  overall_state: string
  boss: OrgBossRow | null
  manager: OrgManagerRow | null
  ready: OrgTaskRow[]
  /** Genuinely blocked rows only — never a task merely waiting on a dependency. */
  blocked: OrgTaskRow[]
  /** Waiting on an upstream task; normal graph progress, not an alarm. */
  waiting: OrgTaskRow[]
  /** Held for the operator; distinct from both of the above. */
  awaitingApproval: OrgTaskRow[]
  failed: OrgTaskRow[]
  next_actions: OrgNextAction[]
  approvals: OrgApprovalRow[]
  active_agents: OrgAgent[]
  render: string | null
  fetchedAt: number
}

// ── Defensive coercion ───────────────────────────────────────────────

const str = (v: unknown, fallback = ''): string => (typeof v === 'string' ? v : fallback)
const num = (v: unknown, fallback = 0): number => (typeof v === 'number' && Number.isFinite(v) ? v : fallback)
const bool = (v: unknown, fallback = false): boolean => (typeof v === 'boolean' ? v : fallback)
const nulStr = (v: unknown): string | null => (typeof v === 'string' && v.length ? v : null)

const obj = (v: unknown): Record<string, unknown> =>
  v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {}

const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : [])

const asRun = (v: unknown): OrgRun | null => {
  const o = obj(v)
  const id = nulStr(o.run_id)

  if (!id) {
    return null
  }

  return {
    run_id: id,
    objective: str(o.objective),
    elapsed_seconds: num(o.elapsed_seconds),
    phase: str(o.phase),
    paused: bool(o.paused),
    stopped: bool(o.stopped),
    active: bool(o.active)
  }
}

const asPhase = (v: unknown): OrgPhase | null => {
  const o = obj(v)

  if (!nulStr(o.label)) {
    return null
  }

  return {
    label: str(o.label),
    detail: str(o.detail),
    steps_total: num(o.steps_total),
    steps_completed: num(o.steps_completed),
    steps_running: num(o.steps_running),
    steps_waiting: num(o.steps_waiting),
    steps_failed: num(o.steps_failed),
    steps_in_review: num(o.steps_in_review),
    steps_queued: num(o.steps_queued)
  }
}

const asCounts = (v: unknown): OrgCounts | null => {
  const o = obj(v)

  if (!Object.keys(o).length) {
    return null
  }

  return {
    total: num(o.total),
    active: num(o.active),
    waiting: num(o.waiting),
    completed: num(o.completed),
    failed: num(o.failed),
    cancelled: num(o.cancelled),
    in_review: num(o.in_review),
    queued: num(o.queued)
  }
}

const asTaskRows = (v: unknown): OrgTaskRow[] =>
  arr(v)
    .map(item => {
      const o = obj(item)

      return {
        task_id: str(o.task_id ?? o.id),
        objective: str(o.objective),
        role_id: nulStr(o.role_id),
        priority: nulStr(o.priority),
        status: nulStr(o.status),
        // `failed` rows carry the cause in `error`/`failure_reason`, blocked rows in `reason`.
        reason: nulStr(o.reason ?? o.error ?? o.failure_reason)
      }
    })
    .filter(row => row.task_id || row.objective)

const asNextActions = (v: unknown): OrgNextAction[] =>
  arr(v).map(item => {
    const o = obj(item)

    return { kind: str(o.kind), task_id: nulStr(o.task_id), detail: str(o.detail) }
  })

const asApprovals = (v: unknown): OrgApprovalRow[] =>
  arr(v).map(item => {
    const o = obj(item)

    return { id: str(o.id), task_id: nulStr(o.task_id), question: str(o.question ?? o.prompt) }
  })

const asBoss = (v: unknown): OrgBossRow | null => {
  const o = obj(v)

  if (!nulStr(o.role_id)) {
    return null
  }

  return {
    role_id: str(o.role_id),
    state: str(o.state, 'unknown'),
    run_active: bool(o.run_active),
    paused: bool(o.paused)
  }
}

const asManager = (v: unknown): OrgManagerRow | null => {
  const o = obj(v)

  if (!nulStr(o.role_id)) {
    return null
  }

  return {
    role_id: str(o.role_id),
    state: str(o.state, 'unknown'),
    current_task_id: nulStr(o.current_task_id),
    current_objective: nulStr(o.current_objective),
    tasks_completed: num(o.tasks_completed),
    tasks_failed: num(o.tasks_failed),
    last_error: nulStr(o.last_error)
  }
}

const asEvents = (rows: unknown[]): OrgEventRow[] =>
  rows.map(item => {
    const o = obj(item)

    return {
      seq: num(o.seq),
      ts: num(o.ts),
      type: str(o.type),
      message: str(o.message),
      task_id: nulStr(o.task_id),
      role_id: nulStr(o.role_id),
      agent_id: nulStr(o.agent_id)
    }
  })

// ── Store ────────────────────────────────────────────────────────────

const $orgStatus = atom<null | OrgStatusView>(null)
const $orgAgents = atom<OrgAgent[]>([])
const $orgEvents = atom<OrgEventRow[]>([])
const $orgError = atom<null | string>(null)

/** Session-local presentation only; never persisted to config. */
export const $orgDockCollapsed = atom(false)

export const getOrgStatus = () => $orgStatus.get()
export const getOrgAgents = () => $orgAgents.get()
export const getOrgEvents = () => $orgEvents.get()

/** True only when the gateway reported a real run — gates the whole console. */
export const orgHasRun = (s: null | OrgStatusView): boolean => !!s?.run?.run_id

export function applyOrgStatus(result: null | OrgStatusResult | undefined) {
  const raw = obj(result?.status)
  const run = asRun(raw.run)

  if (!run) {
    // No run has been accepted yet (or it was stopped and cleared).
    $orgStatus.set(null)

    return
  }

  // `status.blocked` is the union of BLOCKED, WAITING_DEPENDENCY and
  // WAITING_APPROVAL. Splitting it here is what keeps the console honest: a
  // later step waiting on its dependency is normal progress, not a blockage.
  const held = asTaskRows(raw.blocked)

  const view: OrgStatusView = {
    run,
    phase: asPhase(raw.phase),
    counts: asCounts(raw.counts),
    overall_state: str(raw.overall_state, 'unknown'),
    boss: asBoss(raw.boss),
    manager: asManager(raw.manager),
    ready: asTaskRows(raw.ready),
    blocked: held.filter(row => row.status === 'blocked' || !row.status),
    waiting: held.filter(row => row.status === 'waiting_dependency'),
    awaitingApproval: held.filter(row => row.status === 'waiting_approval'),
    failed: asTaskRows(raw.failed),
    next_actions: asNextActions(raw.next_actions),
    approvals: asApprovals(raw.pending_approvals),
    active_agents: arr(raw.active_agents) as OrgAgent[],
    render: nulStr(result?.render),
    fetchedAt: Date.now()
  }

  const previous = $orgStatus.get()

  if (previous && JSON.stringify({ ...previous, fetchedAt: 0 }) === JSON.stringify({ ...view, fetchedAt: 0 })) {
    return
  }

  $orgStatus.set(view)
  $orgError.set(null)
}

export function applyOrgAgents(result: null | OrgAgentsResult | undefined) {
  const agents = arr(result?.agents) as OrgAgent[]
  const previous = $orgAgents.get()

  if (JSON.stringify(previous) === JSON.stringify(agents)) {
    return
  }

  $orgAgents.set(agents)
}

/** Append-only merge keyed on ``seq`` so an incremental poll never duplicates. */
export function appendOrgEvents(result: null | OrgEventsResult | undefined) {
  const incoming = asEvents(arr(result?.events))

  if (!incoming.length) {
    return
  }

  const previous = $orgEvents.get()
  const seen = new Set(previous.map(e => e.seq))
  const merged = [...previous]
  let added = false

  for (const event of incoming) {
    if (seen.has(event.seq)) {
      continue
    }

    merged.push(event)
    added = true
  }

  if (!added) {
    return
  }

  merged.sort((a, b) => a.seq - b.seq)
  $orgEvents.set(merged.length > ORG_EVENT_LIMIT ? merged.slice(merged.length - ORG_EVENT_LIMIT) : merged)
}

export function clearOrgState() {
  $orgStatus.set(null)
  $orgAgents.set([])
  $orgEvents.set([])
  $orgError.set(null)
}

/**
 * Poll the organization surface while a run may be live.
 *
 * `org.status` + `org.agents` are re-fetched on an interval; `org.events` is
 * polled incrementally from the last ``seq`` seen. Failures are recorded as a
 * single non-fatal banner (the gateway may be mid-restart) and never thrown.
 */
export function useOrgPolling(rpc: GatewayRpc, enabled = true) {
  const sinceSeq = useRef(0)
  const inflight = useRef(false)

  const poll = useCallback(() => {
    if (inflight.current) {
      return
    }

    inflight.current = true

    void Promise.all([
      rpc<OrgStatusResult>('org.status', {}),
      rpc<OrgAgentsResult>('org.agents', {}),
      rpc<OrgEventsResult>('org.events', { limit: 50, since_seq: sinceSeq.current })
    ])
      .then(([status, agents, events]) => {
        applyOrgStatus(status)
        applyOrgAgents(agents)
        appendOrgEvents(events)

        const lastSeq = num(obj(events).last_seq, sinceSeq.current)

        if (lastSeq > sinceSeq.current) {
          sinceSeq.current = lastSeq
        }
      })
      .catch((err: unknown) => {
        const message = err instanceof Error ? err.message : String(err ?? 'unknown error')
        $orgError.set(message.slice(0, 200))
      })
      .finally(() => {
        inflight.current = false
      })
  }, [rpc])

  useEffect(() => {
    if (!enabled) {
      return
    }

    poll()
    const timer = setInterval(poll, ORG_POLL_MS)

    return () => clearInterval(timer)
  }, [enabled, poll])

  return { poll }
}

export { $orgAgents, $orgError, $orgEvents, $orgStatus }
