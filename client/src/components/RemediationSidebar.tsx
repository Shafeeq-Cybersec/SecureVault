import { Check, ListChecks } from 'lucide-react'
import type { Finding, Severity } from '../types'
import { SEVERITIES, findingKey } from '../types'

const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: 'var(--critical)',
  HIGH: 'var(--high)',
  MEDIUM: 'var(--medium)',
  LOW: 'var(--low)',
}

const SEV_LABEL: Record<Severity, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
}

export function RemediationSidebar({
  findings,
  isFixed,
  onToggle,
}: {
  findings: Finding[]
  isFixed: (key: string) => boolean
  onToggle: (key: string) => void
}) {
  const total = findings.length
  const done = findings.filter((f) => isFixed(findingKey(f))).length
  const pct = total ? Math.round((done / total) * 100) : 0

  const groups = SEVERITIES.map((sev) => ({
    sev,
    items: findings.filter((f) => f.severity === sev),
  })).filter((g) => g.items.length > 0)

  return (
    <aside className="sidebar">
      <div className="sidebar__header">
        <div className="sidebar__title">
          <ListChecks size={15} />
          Remediation
        </div>
        <div className="sidebar__progress">
          <div className="progress-row">
            <span>Resolved</span>
            <b>
              {done} / {total}
            </b>
          </div>
          <div className="progress-bar">
            <div className="progress-bar__fill" style={{ width: `${pct}%` }} />
          </div>
        </div>
      </div>

      <div className="sidebar__body">
        {groups.map((g) => {
          const groupDone = g.items.filter((f) => isFixed(findingKey(f))).length
          return (
            <div className="remediation-group" key={g.sev}>
              <div className="remediation-group__head">
                <span
                  className="badge__dot"
                  style={{ background: SEV_COLOR[g.sev] }}
                />
                {SEV_LABEL[g.sev]}
                <span className="remediation-group__count">
                  {groupDone}/{g.items.length}
                </span>
              </div>
              {g.items.map((f) => {
                const key = findingKey(f)
                const checked = isFixed(key)
                return (
                  <button
                    key={key}
                    className={`check-item${checked ? ' check-item--checked' : ''}`}
                    onClick={() => onToggle(key)}
                  >
                    <span className="checkbox">
                      {checked && <Check size={11} strokeWidth={3} />}
                    </span>
                    <span className="check-item__body">
                      <span className="check-item__type">{f.secret_type}</span>
                      <span className="check-item__loc">
                        {f.file_path}:{f.line_number}
                      </span>
                    </span>
                  </button>
                )
              })}
            </div>
          )
        })}
      </div>
    </aside>
  )
}
