// Shapes mirrored from the FastAPI backend (server/securevault/models.py).

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

export type Category =
  | 'Likely Secret'
  | 'Potential Secret'
  | 'Example / Template'
  | 'Test Credential'
  | 'Documentation Sample'

const REAL_CATEGORIES = new Set<string>(['Likely Secret', 'Potential Secret'])

/** True for categories that represent a plausibly real production secret. */
export function isRealCategory(category: string): boolean {
  return REAL_CATEGORIES.has(category)
}

export interface Finding {
  file_path: string
  line_number: number
  secret_type: string
  rule_id: string
  severity: Severity
  confidence: number // 0-99 likelihood it's a real, live secret
  confidence_label: string // High | Medium | Low
  category: string
  signals: string[]
  redacted_line: string
  match_preview: string
  remediation: string
}

export interface RateLimitInfo {
  limit: number | null
  remaining: number | null
  reset_epoch: number | null
  reset_in_seconds: number | null
}

export interface ScanResult {
  repository: string
  branch: string
  files_scanned: number
  files_skipped: number
  total_findings: number
  severity_counts: Record<Severity, number>
  category_counts: Record<string, number>
  findings: Finding[]
  rate_limit: RateLimitInfo
  partial: boolean
  errors: string[]
  tree_truncated: boolean
  scanned_at: string
}

export type ScanErrorKind =
  | 'rate_limited'
  | 'not_found'
  | 'auth'
  | 'invalid'
  | 'network'
  | 'server'

export interface ScanError {
  kind: ScanErrorKind
  message: string
  resetInSeconds?: number | null
}

export const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
}

/** Stable identity for a finding, used for React keys and checklist storage. */
export function findingKey(f: Finding): string {
  return `${f.rule_id}:${f.file_path}:${f.line_number}:${f.match_preview}`
}
