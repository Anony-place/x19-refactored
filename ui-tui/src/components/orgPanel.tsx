import { useStore } from '@nanostores/react'
import { Box, stringWidth, Text, useStdout } from '@x19/ink'
import { mix } from '@x19/shared/color'
import { useEffect, useState } from 'react'

import { useGateway } from '../app/gatewayContext.js'
import { $orgAgents, $orgDockCollapsed, $orgEvents, $orgStatus, useOrgPolling } from '../app/orgStore.js'
import type { OrgStatusView } from '../app/orgStore.js'
import { $uiState } from '../app/uiStore.js'
import { orgAgentGlyph, orgStateGlyph } from '../lib/orgGlyph.js'
import { compactPreview } from '../lib/text.js'
import type { Theme } from '../theme.js'

/**
 * The X19 organization console.
 *
 * A dense, information-first panel: the executive hierarchy (X19 → X22 →
 * workers), the task graph counts, what is live right now, what needs the
 * operator, and the event stream. It renders *only* when the gateway reports a
 * real run — there is no placeholder org chart and no synthetic row, so what
 * is on screen is always the runtime.
 *
 * Layout is width-driven rather than fixed: every row truncates to the
 * composer width, and lower-priority sections drop out first on narrow
 * terminals so the hierarchy and task counts always survive.
 */

const LABEL_W = 9
const MAX_LIVE_ROWS = 4
const MAX_EVENT_ROWS = 3

const clockOf = (ts: number): string => {
  if (!ts) {
    return '--:--:--'
  }

  const d = new Date(ts < 1e12 ? ts * 1000 : ts)
  const p = (n: number) => String(n).padStart(2, '0')

  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

const elapsedOf = (seconds: number): string => {
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return '0s'
  }

  const s = Math.floor(seconds)

  if (s < 60) {
    return `${s}s`
  }

  const m = Math.floor(s / 60)

  if (m < 60) {
    return `${m}m${s % 60 ? ` ${s % 60}s` : ''}`
  }

  return `${Math.floor(m / 60)}h${m % 60 ? ` ${m % 60}m` : ''}`
}

/** One dense `label  content` row that truncates to the panel width. */
function Row({
  cols,
  indent = 0,
  label,
  labelColor,
  children
}: {
  cols: number
  indent?: number
  label: string
  labelColor: string
  children: React.ReactNode
}) {
  const width = Math.max(8, cols - indent)

  return (
    <Box flexShrink={0} paddingLeft={indent} width={width}>
      <Text color={labelColor}>{compactPreview(label, LABEL_W).padEnd(LABEL_W)}</Text>
      <Box flexDirection="column" width={Math.max(1, width - LABEL_W)}>
        {children}
      </Box>
    </Box>
  )
}

/** One slice of the task-count summary (`queued 4`, `done 1`, …). */
interface TaskSlice {
  color: (t: Theme) => string
  label: string
  value: number
}

/** `total 8 · queued 4 · running 2 · …` — only non-zero slices are shown. */
function taskSummary(s: OrgStatusView): TaskSlice[] {
  const c = s.counts

  if (!c) {
    return []
  }

  const slices: TaskSlice[] = [
    { label: 'total', value: c.total, color: t => t.color.text },
    { label: 'queued', value: c.queued, color: t => t.color.muted },
    { label: 'running', value: s.phase?.steps_running ?? 0, color: t => t.color.accent },
    // `counts.waiting` is the backend's union of BLOCKED + WAITING_DEPENDENCY +
    // WAITING_APPROVAL — the very same set the server returns as `status.blocked`.
    // Rendering it beside a blocked count showed one task twice, so the slices
    // partition that union instead: whatever is held but not genuinely blocked
    // is waiting (on a dependency, or on the operator).
    { label: 'waiting', value: s.waiting.length + s.awaitingApproval.length, color: t => t.color.label },
    { label: 'review', value: c.in_review, color: t => t.color.statusWarn },
    { label: 'blocked', value: s.blocked.length, color: t => t.color.error },
    { label: 'failed', value: c.failed, color: t => t.color.error },
    { label: 'done', value: c.completed, color: t => t.color.statusGood }
  ]

  return slices.filter(part => part.value > 0 || part.label === 'total')
}

/** A textual progress meter — no colour dependency, degrades on any terminal. */
function meter(done: number, total: number, width: number): string {
  if (!total || width < 4) {
    return ''
  }

  const filled = Math.min(width, Math.round((done / total) * width))

  return `[${'█'.repeat(filled)}${'░'.repeat(width - filled)}] ${done}/${total}`
}

export function OrgPanelView({ cols, status, t }: { cols: number; status: OrgStatusView; t: Theme }) {
  const collapsed = useStore($orgDockCollapsed)
  const agents = useStore($orgAgents)
  const events = useStore($orgEvents)

  const [, forceTick] = useState(0)
  const live = status.phase?.steps_running || 0

  useEffect(() => {
    if (!live) {
      return
    }

    // Re-render once a second so elapsed timers advance between polls.
    const timer = setInterval(() => forceTick(n => n + 1), 1000)

    return () => clearInterval(timer)
  }, [live])

  const state = orgStateGlyph(status.overall_state, t)
  const run = status.run!
  const header = `X19 · ${run.objective || run.run_id}`
  const headerRight = `${state.glyph} ${status.overall_state}${run.paused ? ' · paused' : ''} · ${elapsedOf(run.elapsed_seconds)}`
  const headerRoom = Math.max(12, cols - stringWidth(headerRight) - 3)

  const workers = agents.filter(a => String(a.kind ?? '') === 'worker')
  const liveWorkers = workers.filter(a => a.state === 'active')

  if (collapsed) {
    const bits = taskSummary(status)
      .map(part => `${part.label} ${part.value}`)
      .join(' · ')

    const line = `${header.slice(0, headerRoom)}  ${bits}`

    return (
      <Box backgroundColor={mix(t.color.statusBg, t.color.shellDollar, 0.12)} flexDirection="column" flexShrink={0} width={cols}>
        <Text bold color={t.color.accent} wrap="truncate-end">{`▸ ${line}`}</Text>
        <Text color={t.color.muted} wrap="truncate-end">{`  ${headerRight} · Ctrl+G expand`}</Text>
      </Box>
    )
  }

  const needsAttention =
    status.blocked.length > 0 ||
    status.failed.length > 0 ||
    status.awaitingApproval.length > 0 ||
    status.approvals.length > 0

  const narrow = cols < 62

  return (
    <Box backgroundColor={mix(t.color.statusBg, t.color.shellDollar, 0.12)} flexDirection="column" flexShrink={0} width={cols}>
      <Text bold color={t.color.accent} wrap="truncate-end">{`▾ ${compactPreview(header, headerRoom)}`}</Text>
      <Text color={state.color(t)} wrap="truncate-end">{`  ${headerRight}`}</Text>

      {/* ── hierarchy: X19 → X22 → workers, each from real registry state ── */}
      <Row cols={cols} label="boss" labelColor={t.color.label}>
        <Text wrap="truncate-end">
          <Text color={orgAgentGlyph(status.boss?.state, t).color(t)}>
            {`${orgAgentGlyph(status.boss?.state, t).glyph} `}
          </Text>
          <Text color={t.color.text}>{`X19 ${status.boss?.state ?? 'unknown'}`}</Text>
          <Text color={t.color.muted}>{` · executive orchestrator · ${elapsedOf(run.elapsed_seconds)}`}</Text>
        </Text>
      </Row>

      <Row cols={cols} label="manager" labelColor={t.color.label}>
        <Text wrap="truncate-end">
          <Text color={orgAgentGlyph(status.manager?.state, t).color(t)}>
            {`${orgAgentGlyph(status.manager?.state, t).glyph} `}
          </Text>
          <Text color={t.color.text}>{`X22 ${status.manager?.state ?? 'unknown'}`}</Text>
          <Text color={t.color.muted}>
            {status.manager?.current_objective
              ? ` · ${compactPreview(status.manager.current_objective, Math.max(10, cols - 40))}`
              : ` · ${status.manager?.tasks_completed ?? 0} done${status.manager?.tasks_failed ? ` · ${status.manager.tasks_failed} failed` : ''}`}
          </Text>
        </Text>
      </Row>

      <Row cols={cols} label="workers" labelColor={t.color.label}>
        <Text wrap="truncate-end">
          <Text color={t.color.text}>{`${liveWorkers.length} live`}</Text>
          <Text color={t.color.muted}>{` · ${workers.length} registered`}</Text>
        </Text>
      </Row>

      {/* ── task graph ── */}
      <Row cols={cols} label="tasks" labelColor={t.color.label}>
        <Text wrap="truncate-end">
          {taskSummary(status).map((part, i) => (
            <Text key={part.label}>
              {i > 0 ? <Text color={t.color.muted}> · </Text> : null}
              <Text color={t.color.muted}>{`${part.label} `}</Text>
              <Text color={part.color(t)}>{part.value}</Text>
            </Text>
          ))}
        </Text>
        {status.phase && !narrow && status.phase.steps_total > 0 ? (
          <Text color={t.color.muted} wrap="truncate-end">
            {meter(status.phase.steps_completed, status.phase.steps_total, Math.min(20, Math.max(6, cols - LABEL_W - 26)))}
          </Text>
        ) : null}
      </Row>

      {/* ── what is running right now ── */}
      {liveWorkers.length ? (
        <Row cols={cols} label="live" labelColor={t.color.label}>
          {liveWorkers.slice(0, MAX_LIVE_ROWS).map(agent => (
            <Text key={String(agent.agent_id ?? agent.role_id)} wrap="truncate-end">
              <Text color={t.color.accent}>● </Text>
              <Text color={t.color.text}>{compactPreview(String(agent.role_id ?? agent.agent_id ?? ''), 10).padEnd(10)}</Text>
              <Text color={t.color.muted}>
                {compactPreview(String(agent.current_objective ?? 'starting'), Math.max(12, cols - LABEL_W - 26))}
              </Text>
              <Text color={t.color.label}>
                {` ${elapsedOf(Number(agent.running_seconds ?? 0))}`}
              </Text>
            </Text>
          ))}
        </Row>
      ) : null}

      {/* ── attention: only what genuinely needs someone. A task merely waiting
          on an upstream dependency is counted under `tasks`, never shown here. ── */}
      {needsAttention ? (
        <Row cols={cols} label="attention" labelColor={t.color.error}>
          {status.awaitingApproval.map(row => (
            <Text key={row.task_id} wrap="truncate-end">
              <Text color={t.color.warn}>{`⚑ ${compactPreview(String(row.role_id ?? 'task'), 10).padEnd(10)}`}</Text>
              <Text color={t.color.text}>
                {compactPreview(row.objective, Math.max(12, cols - LABEL_W - 34))}
              </Text>
              <Text color={t.color.muted}> · awaiting your decision</Text>
            </Text>
          ))}
          {status.approvals.map(a => (
            <Text color={t.color.warn} key={a.id} wrap="truncate-end">
              {`⚑ approval · ${compactPreview(a.question || a.task_id || a.id, Math.max(12, cols - LABEL_W - 12))}`}
            </Text>
          ))}
          {status.blocked.map(row => (
            <Text key={row.task_id} wrap="truncate-end">
              <Text color={t.color.error}>{`⊘ ${compactPreview(String(row.role_id ?? 'task'), 10).padEnd(10)}`}</Text>
              <Text color={t.color.text}>{compactPreview(row.objective, Math.max(12, cols - LABEL_W - 14))}</Text>
              {row.reason ? <Text color={t.color.muted}>{` · ${compactPreview(row.reason, 26)}`}</Text> : null}
            </Text>
          ))}
          {status.failed.map(row => (
            <Text key={row.task_id} wrap="truncate-end">
              <Text color={t.color.error}>{`✗ ${compactPreview(String(row.role_id ?? 'task'), 10).padEnd(10)}`}</Text>
              <Text color={t.color.text}>{compactPreview(row.objective, Math.max(12, cols - LABEL_W - 14))}</Text>
              {row.reason ? <Text color={t.color.muted}>{` · ${compactPreview(row.reason, 26)}`}</Text> : null}
            </Text>
          ))}
        </Row>
      ) : null}

      {/* ── the runtime's own derived next action ── */}
      {!narrow && status.next_actions.length ? (
        <Row cols={cols} label="next" labelColor={t.color.label}>
          <Text color={t.color.thinking} wrap="truncate-end">
            {compactPreview(
              status.next_actions.map(a => `${a.kind}: ${a.detail}`).join(' · '),
              Math.max(16, cols - LABEL_W - 2)
            )}
          </Text>
        </Row>
      ) : null}

      {/* ── event stream (newest last, real seq/ts from the bus) ── */}
      {!narrow && events.length ? (
        <Row cols={cols} label="events" labelColor={t.color.label}>
          {events.slice(-MAX_EVENT_ROWS).map(event => (
            <Text key={event.seq} wrap="truncate-end">
              <Text color={t.color.muted}>{`${clockOf(event.ts)} `}</Text>
              <Text color={t.color.label}>{compactPreview(event.type, 22).padEnd(22)}</Text>
              <Text color={t.color.muted}>
                {compactPreview(
                  [event.role_id ?? event.agent_id, event.message].filter(Boolean).join(' · '),
                  Math.max(10, cols - LABEL_W - 34)
                )}
              </Text>
            </Text>
          ))}
        </Row>
      ) : null}

      <Text color={t.color.muted} wrap="truncate-end">{`  Ctrl+G collapse · ${status.phase?.detail ?? ''}`}</Text>
    </Box>
  )
}

/** Docked console: polls `org.*` and renders nothing until a run exists. */
export function OrgConsole({ cols }: { cols: number }) {
  const { rpc } = useGateway()
  const { theme } = useStore($uiState)
  const status = useStore($orgStatus)
  const { stdout } = useStdout()

  // Only poll while the terminal is attached; the gateway owns all state.
  useOrgPolling(rpc, !!stdout)

  const width = Math.max(1, cols)

  if (!status?.run?.run_id) {
    return null
  }

  return <OrgPanelView cols={width} status={status} t={theme} />
}
