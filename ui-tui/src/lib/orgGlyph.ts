import type { Theme } from '../theme.js'

/**
 * Glyph + colour lookup for the X19 organization lifecycle.
 *
 * The org task vocabulary is *not* the subagent vocabulary: a task moves
 * QUEUED → PLANNED → ASSIGNED → RUNNING → (WAITING_DEPENDENCY | BLOCKED |
 * WAITING_APPROVAL) → IN_REVIEW → COMPLETED | FAILED | CANCELLED. Keeping this
 * map separate from `subagentGlyph.ts` means a task waiting on a dependency is
 * never painted as a "queued agent", and the console's colours stay honest.
 *
 * Everything resolves through the theme's semantic tokens so the palette stays
 * contrast-aware on both light and dark surfaces.
 */

export type OrgTaskStatus =
  | 'assigned'
  | 'blocked'
  | 'cancelled'
  | 'completed'
  | 'failed'
  | 'in_review'
  | 'planned'
  | 'queued'
  | 'running'
  | 'waiting_approval'
  | 'waiting_dependency'

export type OrgAgentState = 'active' | 'completed' | 'failed' | 'idle' | 'stale' | 'unknown'

interface Glyph {
  color: (t: Theme) => string
  glyph: string
  label: string
}

const TASK_GLYPHS: Record<OrgTaskStatus, Glyph> = {
  queued: { color: t => t.color.muted, glyph: '○', label: 'queued' },
  planned: { color: t => t.color.muted, glyph: '○', label: 'planned' },
  assigned: { color: t => t.color.label, glyph: '◦', label: 'assigned' },
  running: { color: t => t.color.accent, glyph: '●', label: 'running' },
  waiting_dependency: { color: t => t.color.label, glyph: '⧗', label: 'waiting' },
  blocked: { color: t => t.color.error, glyph: '⊘', label: 'blocked' },
  waiting_approval: { color: t => t.color.warn, glyph: '⚑', label: 'approval' },
  in_review: { color: t => t.color.statusWarn, glyph: '◐', label: 'review' },
  completed: { color: t => t.color.statusGood, glyph: '✓', label: 'done' },
  failed: { color: t => t.color.error, glyph: '✗', label: 'failed' },
  cancelled: { color: t => t.color.muted, glyph: '■', label: 'cancelled' }
}

const AGENT_GLYPHS: Record<OrgAgentState, Glyph> = {
  active: { color: t => t.color.accent, glyph: '●', label: 'active' },
  idle: { color: t => t.color.muted, glyph: '○', label: 'idle' },
  completed: { color: t => t.color.statusGood, glyph: '✓', label: 'done' },
  failed: { color: t => t.color.error, glyph: '✗', label: 'failed' },
  stale: { color: t => t.color.warn, glyph: '⌛', label: 'stale' },
  unknown: { color: t => t.color.muted, glyph: '·', label: 'unknown' }
}

/** Neutral fallback for a status a newer/older daemon introduced. An unknown
 *  status is not a failure, so it is deliberately not painted red. */
const UNKNOWN: Glyph = { color: t => t.color.muted, glyph: '·', label: 'unknown' }

/** The wire uses both `waiting_dependency` and the shorter `waiting`. */
const normalize = (status: string): string => status.toLowerCase().replace(/[\s-]+/g, '_')

export const orgTaskGlyph = (status: string | null | undefined, t: Theme): Glyph =>
  TASK_GLYPHS[normalize(status ?? '') as OrgTaskStatus] ?? UNKNOWN

export const orgAgentGlyph = (state: string | null | undefined, t: Theme): Glyph =>
  AGENT_GLYPHS[normalize(state ?? '') as OrgAgentState] ?? UNKNOWN

/** Overall run state — the single word in the console header. */
export const orgStateGlyph = (state: string | null | undefined, t: Theme): Glyph => {
  const key = normalize(state ?? '')

  if (key === 'failed' || key === 'error' || key === 'blocked') {
    return { color: t => t.color.error, glyph: '⊘', label: key }
  }

  if (key === 'awaiting_operator' || key === 'waiting_approval') {
    return { color: t => t.color.warn, glyph: '⚑', label: key }
  }

  if (key === 'completed' || key === 'done') {
    return { color: t => t.color.statusGood, glyph: '✓', label: key }
  }

  if (key === 'paused') {
    return { color: t => t.color.warn, glyph: '⏸', label: key }
  }

  if (key === 'stopped' || key === 'cancelled') {
    return { color: t => t.color.muted, glyph: '■', label: key }
  }

  if (key === 'running' || key === 'active') {
    return { color: t => t.color.accent, glyph: '●', label: key }
  }

  return { color: t => t.color.label, glyph: '◦', label: key || 'unknown' }
}

export type { Glyph as OrgGlyph }
