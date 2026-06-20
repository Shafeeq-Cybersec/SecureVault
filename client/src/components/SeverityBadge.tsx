import type { Severity } from '../types'

const LABELS: Record<Severity, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`badge badge--${severity.toLowerCase()}`}>
      <span className="badge__dot" />
      {LABELS[severity]}
    </span>
  )
}
