import { Download, TriangleAlert } from 'lucide-react'
import type { ScanResult } from '../types'
import { downloadReport } from '../lib/export'
import { SummaryCards } from './SummaryCards'
import { FindingsList } from './FindingsList'
import { RemediationSidebar } from './RemediationSidebar'

export function Results({
  result,
  elapsedMs,
  isFixed,
  onToggleFixed,
}: {
  result: ScanResult
  elapsedMs: number
  isFixed: (key: string) => boolean
  onToggleFixed: (key: string) => void
}) {
  const plural = result.total_findings === 1 ? '' : 's'

  return (
    <div className="results fade-in">
      <div className="results__main">
        <div className="results__header">
          <div>
            <h1 className="results__title">
              {result.partial ? 'Partial scan results' : 'Scan complete'}
            </h1>
            <p className="results__subtitle">
              Found {result.total_findings} potential secret{plural} in{' '}
              <b>{result.repository}</b> · branch {result.branch}
            </p>
          </div>
          <button
            className="btn btn--secondary"
            onClick={() => downloadReport(result)}
          >
            <Download size={15} />
            Export
          </button>
        </div>

        <SummaryCards result={result} elapsedMs={elapsedMs} />

        {(result.partial || result.errors.length > 0) && (
          <div className="state__hint" style={{ alignSelf: 'flex-start' }}>
            <TriangleAlert size={14} style={{ color: 'var(--high)' }} />
            {result.errors[0] ??
              'Scan was incomplete — some files may not have been scanned.'}
          </div>
        )}

        <FindingsList
          findings={result.findings}
          isFixed={isFixed}
          onToggleFixed={onToggleFixed}
        />
      </div>

      <RemediationSidebar
        findings={result.findings}
        isFixed={isFixed}
        onToggle={onToggleFixed}
      />
    </div>
  )
}
