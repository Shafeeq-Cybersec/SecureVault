import { Check, ChevronRight, Sparkles, Square } from 'lucide-react'
import type { Finding } from '../types'
import { isRealCategory } from '../types'
import { SeverityBadge } from './SeverityBadge'
import { CategoryChip } from './CategoryChip'
import { ConfidenceMeter } from './ConfidenceMeter'
import { CodeBlock } from './CodeBlock'
import { CopyButton } from './CopyButton'

export function FindingRow({
  finding,
  open,
  fixed,
  onToggle,
  onToggleFixed,
}: {
  finding: Finding
  open: boolean
  fixed: boolean
  onToggle: () => void
  onToggleFixed: () => void
}) {
  const isReal = isRealCategory(finding.category)

  return (
    <div
      className={`finding${open ? ' finding--open' : ''}${
        fixed ? ' finding--fixed' : ''
      }`}
    >
      <button className="finding__row" onClick={onToggle} aria-expanded={open}>
        <SeverityBadge severity={finding.severity} />
        <div className="finding__main">
          <div className="finding__titlerow">
            <span className="finding__type">{finding.secret_type}</span>
            <CategoryChip category={finding.category} />
          </div>
          <span className="finding__path" title={finding.file_path}>
            {finding.file_path}:{finding.line_number}
          </span>
        </div>
        <ConfidenceMeter value={finding.confidence} label={finding.confidence_label} />
        <span className="finding__chevron">
          <ChevronRight size={16} />
        </span>
      </button>

      {open && (
        <div className="finding__panel">
          <div className="finding__panel-inner">
            <div>
              <div className="panel-section-label">Detected line</div>
              <CodeBlock
                code={finding.redacted_line}
                filePath={finding.file_path}
                lineNumber={finding.line_number}
              />
            </div>

            <div className="panel-meta">
              <div className="panel-meta__item">
                {isReal ? 'Secret' : 'Value'}
                <span className="secret-chip">{finding.match_preview}</span>
              </div>
              <div className="panel-meta__item">
                Rule <span className="mono">{finding.rule_id}</span>
              </div>
              <CopyButton text={finding.file_path} label="Copy path" />
            </div>

            <div className="score-row">
              <div className="score-row__item">
                <span className="score-row__label">Category</span>
                <CategoryChip category={finding.category} />
              </div>
              <div className="score-row__item">
                <span className="score-row__label">Confidence</span>
                <ConfidenceMeter
                  value={finding.confidence}
                  label={finding.confidence_label}
                  size="lg"
                />
              </div>
            </div>

            {finding.signals.length > 0 && (
              <div>
                <div className="panel-section-label">
                  <Sparkles size={12} />
                  Why this score
                </div>
                <ul className="signals">
                  {finding.signals.map((s, i) => (
                    <li key={i} className="signals__item">
                      <span className="signals__dot" />
                      {s}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div>
              <div className="panel-section-label">Remediation</div>
              <div className="remediation">
                <p className="remediation__text">{finding.remediation}</p>
              </div>
            </div>

            <div className="panel-fix">
              <button
                type="button"
                className={`copy-btn${fixed ? ' copy-btn--copied' : ''}`}
                onClick={onToggleFixed}
              >
                {fixed ? <Check size={12} /> : <Square size={12} />}
                {fixed ? 'Marked as fixed' : 'Mark as fixed'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
