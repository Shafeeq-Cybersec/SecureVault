import type { ScanError, ScanResult } from './types'

const API_BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

/** Map a backend HTTP error into a typed, user-facing ScanError. */
function mapError(status: number, detail: unknown): ScanError {
  // FastAPI HTTPException with a dict detail -> { detail: { error, message, ... } }
  if (detail && typeof detail === 'object') {
    const d = detail as Record<string, unknown>
    const message = typeof d.message === 'string' ? d.message : undefined
    const error = typeof d.error === 'string' ? d.error : undefined

    if (error === 'rate_limited' || status === 429) {
      return {
        kind: 'rate_limited',
        message: message ?? 'GitHub API rate limit exceeded.',
        resetInSeconds:
          typeof d.reset_in_seconds === 'number' ? d.reset_in_seconds : null,
      }
    }
    if (error === 'RepoNotFoundError' || status === 404) {
      return { kind: 'not_found', message: message ?? 'Repository not found.' }
    }
    if (error === 'AuthError' || status === 401) {
      return { kind: 'auth', message: message ?? 'GitHub authentication failed.' }
    }
    if (error === 'InvalidTargetError') {
      return { kind: 'invalid', message: message ?? 'Invalid repository target.' }
    }
    if (message) return { kind: 'server', message }
  }

  // 422 validation error from FastAPI
  if (status === 422) {
    return {
      kind: 'invalid',
      message: 'That does not look like a valid repository. Use owner/repo.',
    }
  }
  if (status === 404) return { kind: 'not_found', message: 'Repository not found.' }
  if (status === 401) return { kind: 'auth', message: 'GitHub authentication failed.' }
  if (status === 429) {
    return { kind: 'rate_limited', message: 'GitHub API rate limit exceeded.' }
  }
  return {
    kind: 'server',
    message: `The scan failed (HTTP ${status}). Please try again.`,
  }
}

export async function scanRepo(
  target: string,
  token?: string,
): Promise<ScanResult> {
  let res: Response
  try {
    res = await fetch(`${API_BASE}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, token: token?.trim() || null }),
    })
  } catch {
    const err: ScanError = {
      kind: 'network',
      message: `Could not reach the SecureVault backend at ${API_BASE}. Make sure it is running.`,
    }
    throw err
  }

  if (res.ok) {
    return (await res.json()) as ScanResult
  }

  let detail: unknown = null
  try {
    const body = await res.json()
    detail = body?.detail ?? body
  } catch {
    /* non-JSON error body */
  }
  throw mapError(res.status, detail)
}
