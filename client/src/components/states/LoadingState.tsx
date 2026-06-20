import { useEffect, useState } from 'react'
import { Check } from 'lucide-react'

const PHASES = [
  'Connecting to GitHub',
  'Fetching repository tree',
  'Scanning files for secrets',
]

export function LoadingState({ repo }: { repo: string }) {
  const [phase, setPhase] = useState(0)

  useEffect(() => {
    const t1 = setTimeout(() => setPhase(1), 700)
    const t2 = setTimeout(() => setPhase(2), 1600)
    return () => {
      clearTimeout(t1)
      clearTimeout(t2)
    }
  }, [])

  return (
    <div className="loading">
      <div className="progress-phases">
        <div className="progress-phases__head">
          <span
            className="spinner"
            style={{
              borderColor: 'var(--accent-border)',
              borderTopColor: 'var(--accent-text)',
            }}
          />
          <span className="progress-phases__title">
            Scanning{' '}
            <span className="mono" style={{ color: 'var(--text-secondary)' }}>
              {repo}
            </span>
          </span>
        </div>
        <div className="phase-list">
          {PHASES.map((p, i) => (
            <div
              key={p}
              className={`phase${i < phase ? ' phase--done' : ''}${
                i === phase ? ' phase--active' : ''
              }`}
            >
              <span className="phase__dot">
                {i < phase ? (
                  <Check size={14} style={{ color: 'var(--success)' }} />
                ) : i === phase ? (
                  <span className="spinner" />
                ) : (
                  <span className="phase__pending" />
                )}
              </span>
              {p}
              {i === phase ? '…' : ''}
            </div>
          ))}
        </div>
      </div>

      <div className="skeleton-cards">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="skeleton skeleton-card" />
        ))}
      </div>
      <div className="skeleton-list">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="skeleton skeleton-row" />
        ))}
      </div>
    </div>
  )
}
