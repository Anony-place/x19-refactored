import type {
  ActionResponse,
  ActionStatusResponse,
  AudioSpeakResponse,
  AudioTranscriptionResponse,
  AudioTtsLeaseResponse,
  BackendUpdateCheckResponse,
  CuratorStatusResponse,
  DebugShareResponse,
  ElevenLabsVoicesResponse,
  MemoryProviderConfig,
  MemoryProviderOAuthStatus,
  MemoryStatusResponse
} from '@/types/x19'

import { capabilityScoped, x19Api, type ProfileScope, profileScoped } from './client'

export const AUDIO_SPEAK_MIN_REQUEST_TIMEOUT_MS = 180_000
export const AUDIO_SPEAK_MAX_REQUEST_TIMEOUT_MS = 600_000
const AUDIO_SPEAK_TIMEOUT_MS_PER_CHAR = 35

export function audioSpeakRequestTimeoutMs(text: string): number {
  const estimated = Math.max(
    AUDIO_SPEAK_MIN_REQUEST_TIMEOUT_MS,
    Math.ceil(String(text || '').length * AUDIO_SPEAK_TIMEOUT_MS_PER_CHAR)
  )

  return Math.min(AUDIO_SPEAK_MAX_REQUEST_TIMEOUT_MS, estimated)
}

export const AUDIO_TRANSCRIBE_MIN_REQUEST_TIMEOUT_MS = 180_000
export const AUDIO_TRANSCRIBE_MAX_REQUEST_TIMEOUT_MS = 600_000
// The transcribe payload is the base64 audio data URL itself, so its string
// length tracks clip size. ~0.1ms/char keeps short clips at the floor while
// letting multi-minute recordings scale toward the cap (a base64 char is
// ~0.75 bytes, so at 128kbps ≈ 21k chars/s of audio this budgets ~2s of
// timeout per 1s of audio before the cap clamps it).
const AUDIO_TRANSCRIBE_TIMEOUT_MS_PER_CHAR = 0.1

export function audioTranscribeRequestTimeoutMs(dataUrl: string): number {
  const estimated = Math.max(
    AUDIO_TRANSCRIBE_MIN_REQUEST_TIMEOUT_MS,
    Math.ceil(String(dataUrl || '').length * AUDIO_TRANSCRIBE_TIMEOUT_MS_PER_CHAR)
  )

  return Math.min(AUDIO_TRANSCRIBE_MAX_REQUEST_TIMEOUT_MS, estimated)
}

// surface=declared serves the curated desktop schema; the dashboard consumes the raw plugin schema.
export function getMemoryProviderConfig(provider: string, profile?: null | string): Promise<MemoryProviderConfig> {
  return x19Api<MemoryProviderConfig>({
    ...profileScoped(profile),
    path: `/api/memory/providers/${encodeURIComponent(provider)}/config?surface=declared`
  })
}

export function saveMemoryProviderConfig(
  provider: string,
  values: Record<string, string>,
  profile?: null | string
): Promise<{ ok: boolean }> {
  return x19Api<{ ok: boolean }>({
    ...profileScoped(profile),
    path: `/api/memory/providers/${encodeURIComponent(provider)}/config?surface=declared`,
    method: 'PUT',
    body: { values }
  })
}

// Memory-provider OAuth connect (provider-keyed; 404s for providers without an
// OAuth flow). Profile-scoped: the grant lands in the active profile's config.
export function startMemoryProviderOAuth(
  provider: string,
  profile?: null | string
): Promise<MemoryProviderOAuthStatus> {
  return x19Api<MemoryProviderOAuthStatus>({
    ...profileScoped(profile),
    path: `/api/memory/providers/${encodeURIComponent(provider)}/oauth/start`,
    method: 'POST'
  })
}

export function getMemoryProviderOAuthStatus(
  provider: string,
  profile?: null | string
): Promise<MemoryProviderOAuthStatus> {
  return x19Api<MemoryProviderOAuthStatus>({
    ...profileScoped(profile),
    path: `/api/memory/providers/${encodeURIComponent(provider)}/oauth/status`
  })
}

// ---------------------------------------------------------------------------
// Memory data + curator (parity with `x19 memory` / `x19 curator`).
// ---------------------------------------------------------------------------

export function getMemoryStatus(): Promise<MemoryStatusResponse> {
  return x19Api<MemoryStatusResponse>({
    ...profileScoped(),
    path: '/api/memory'
  })
}

export function resetMemory(target: 'all' | 'memory' | 'user'): Promise<{ ok: boolean; deleted: string[] }> {
  return x19Api<{ ok: boolean; deleted: string[] }>({
    ...profileScoped(),
    path: '/api/memory/reset',
    method: 'POST',
    body: { target }
  })
}

export function getCuratorStatus(): Promise<CuratorStatusResponse> {
  return x19Api<CuratorStatusResponse>({
    ...profileScoped(),
    path: '/api/curator'
  })
}

export function setCuratorPaused(paused: boolean): Promise<{ ok: boolean; paused: boolean }> {
  return x19Api<{ ok: boolean; paused: boolean }>({
    ...profileScoped(),
    path: '/api/curator/paused',
    method: 'PUT',
    body: { paused }
  })
}

export function runCurator(): Promise<ActionResponse> {
  return x19Api<ActionResponse>({
    ...profileScoped(),
    path: '/api/curator/run',
    method: 'POST',
    body: {}
  })
}

export function restartGateway(): Promise<ActionResponse> {
  return x19Api<ActionResponse>({
    ...profileScoped(),
    path: '/api/gateway/restart',
    method: 'POST'
  })
}

export function updateX19(): Promise<ActionResponse> {
  return x19Api<ActionResponse>({
    ...profileScoped(),
    path: '/api/x19/update',
    method: 'POST'
  })
}

/** Query the connected backend's own update state. In remote mode this is the
 *  authoritative source for the backend's behind-count + "what's changed",
 *  distinct from the Electron client clone's git state. */
export function checkX19Update(force = false): Promise<BackendUpdateCheckResponse> {
  return x19Api<BackendUpdateCheckResponse>({
    ...profileScoped(),
    path: `/api/x19/update/check${force ? '?force=true' : ''}`
  })
}

export function getActionStatus(name: string, lines = 200, profile?: ProfileScope): Promise<ActionStatusResponse> {
  return window.x19Desktop.api<ActionStatusResponse>({
    ...capabilityScoped(profile),
    path: `/api/actions/${encodeURIComponent(name)}/status?lines=${Math.max(1, lines)}`
  })
}

export function transcribeAudio(dataUrl: string, mimeType?: string): Promise<AudioTranscriptionResponse> {
  return x19Api<AudioTranscriptionResponse>({
    path: '/api/audio/transcribe',
    method: 'POST',
    ...profileScoped(),
    body: {
      data_url: dataUrl,
      mime_type: mimeType
    },
    // Transcription blocks until provider STT, file handling, and response
    // encoding finish. Remote providers and long clips regularly exceed the
    // default 15s Electron backend timeout.
    timeoutMs: audioTranscribeRequestTimeoutMs(dataUrl)
  })
}

export function speakText(text: string): Promise<AudioSpeakResponse> {
  return x19Api<AudioSpeakResponse>({
    ...profileScoped(),
    path: '/api/audio/speak',
    method: 'POST',
    body: { text },
    // TTS blocks until provider synthesis, file read, and base64 encoding
    // finish. Remote providers and large messages regularly exceed the
    // default 15s Electron backend timeout.
    timeoutMs: audioSpeakRequestTimeoutMs(text)
  })
}

// Acquiring a lease pre-loads the configured TTS engine. For local engines
// that is a model load and, on a fresh install, a voice download — well past
// the default 15s Electron backend timeout.
export const AUDIO_TTS_LEASE_REQUEST_TIMEOUT_MS = 180_000

/**
 * Tell the backend a speech-output toggle flipped so it can warm the TTS engine
 * (`active: true`) or release it once no surface needs it (`active: false`).
 * `lease` names the toggle — `desktop:read-aloud`, `desktop:conversation`.
 */
export function setTtsLease(lease: string, active: boolean): Promise<AudioTtsLeaseResponse> {
  return x19Api<AudioTtsLeaseResponse>({
    ...profileScoped(),
    path: '/api/audio/tts-lease',
    method: 'POST',
    body: { active, lease },
    timeoutMs: AUDIO_TTS_LEASE_REQUEST_TIMEOUT_MS
  })
}

export function getElevenLabsVoices(profile?: null | string): Promise<ElevenLabsVoicesResponse> {
  return x19Api<ElevenLabsVoicesResponse>({
    path: '/api/audio/elevenlabs/voices',
    ...profileScoped(profile)
  })
}

/** `gh` CLI presence + auth state, for the composer's GitHub skill pill
 *  (GitHub is deliberately not an MCP — the github/* skills are the
 *  integration). Backend caches for 5 minutes; `refresh` bypasses. */
export function getGhAuthStatus(refresh = false): Promise<{ available: boolean; authenticated: boolean }> {
  return x19Api<{ available: boolean; authenticated: boolean }>({
    ...profileScoped(),
    path: `/api/git/gh-auth${refresh ? '?refresh=true' : ''}`
  })
}

// ---------------------------------------------------------------------------
// Maintenance operations (parity with `x19 doctor` / `x19 security
// audit` / `x19 backup` / `x19 debug share` and the dashboard System
// page). All except debug share are spawn-based background actions tailed via
// getActionStatus().
// ---------------------------------------------------------------------------

export function runDoctor(): Promise<ActionResponse> {
  return x19Api<ActionResponse>({ path: '/api/ops/doctor', method: 'POST', body: {} })
}

export function runSecurityAudit(): Promise<ActionResponse> {
  return x19Api<ActionResponse>({ path: '/api/ops/security-audit', method: 'POST', body: {} })
}

export function runBackup(): Promise<ActionResponse & { archive?: string }> {
  return x19Api<ActionResponse & { archive?: string }>({
    path: '/api/ops/backup',
    method: 'POST',
    body: {}
  })
}

export function runDebugShare(): Promise<DebugShareResponse> {
  return x19Api<DebugShareResponse>({
    path: '/api/ops/debug-share',
    method: 'POST',
    body: {},
    // Synchronous upload of report + logs to the paste service.
    timeoutMs: 120_000
  })
}
