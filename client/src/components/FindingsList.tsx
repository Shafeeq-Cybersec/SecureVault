import { useMemo, useState } from 'react'
import type { Finding, Severity } from '../types'
import { SEVERITIES, SEVERITY_RANK, findingKey } from '../types'
import { FindingRow } from './FindingRow'

type Filter = Severity | 'ALL'

export function FindingsList({
  findings,
  isFixed,
  onToggleFixed,
}: {
  findings: Finding[]
  isFixed: (key: string) => boolean
  onToggleFixed: (key: string) => void
}) {
  const [filter, setFilter] = useState<Filter>('ALL')
  const [openKey, setOpenKey] = useState<string | null>(null)

  const counts = useMemo(() => {
    const c: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
    for (const f of findings) c[f.severity] += 1
    return c
  }, [findings])

  const sorted = useMemo(
    () =>
      [...findings].sort(
        (a, b) =>
          SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
          a.file_path.localeCompare(b.file_path) ||
          a.line_number - b.line_number,
      ),
    [findings],
  )

  const visible = filter === 'ALL' ? sorted : sorted.filter((f) => f.severity === filter)
  const presentSeverities = SEVERITIES.filter((s) => counts[s] > 0)

  return (
    <div className="findings">
      <div className="findings__toolbar">
        <div className="filter-chips">
          <button
            className={`filter-chip${filter === 'ALL' ? ' filter-chip--active' : ''}`}
            onClick={() => setFilter('ALL')}
          >
            All <span className="filter-chip__count">{findings.length}</span>
          </button>
          {presentSeverities.map((s) => (
            <button
              key={s}
              className={`filter-chip${filter === s ? ' filter-chip--active' : ''}`}
              onClick={() => setFilter(s)}
            >
              {s.charAt(0) + s.slice(1).toLowerCase()}
              <span className="filter-chip__count">{counts[s]}</span>
            </button>
          ))}
        </div>
        <span className="results__subtitle">{visible.length} shown</span>
      </div>

      <div className="findings__list">
        {visible.map((f) => {
          const key = findingKey(f)
          return (
            <FindingRow
              key={key}
              finding={f}
              open={openKey === key}
              fixed={isFixed(key)}
              onToggle={() => setOpenKey(openKey === key ? null : key)}
              onToggleFixed={() => onToggleFixed(key)}
            />
          )
        })}
      </div>
    </div>
  )
}
