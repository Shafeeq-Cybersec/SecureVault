import type { ReactNode } from 'react'
import {
  AlertTriangle,
  Clock,
  KeyRound,
  Plus,
  RotateCcw,
  SearchX,
  WifiOff,
} from 'lucide-react'
import type { ScanError } from '../../types'

function describe(error: ScanError): { title: string; icon: ReactNode; hint?: string } {
  switch (error.kind) {
    case 'rate_limited':
      return {
        title: 'Rate limit reached',
        icon: <Clock size={26} />,
        hint: 'Add a GitHub token in the header to raise your limit to 5,000 requests/hour.',
      }
    case 'not_found':
      return {
        title: 'Repository not found',
        icon: <SearchX size={26} />,
        hint: 'Double-check the owner/repo spelling. For private repos, add a token with repo scope.',
      }
    case 'auth':
      return {
        title: 'Authentication failed',
        icon: <KeyRound size={26} />,
        hint: 'The token may be invalid, expired, or missing the required scope.',
      }
    case 'invalid':
      return { title: 'Invalid repository', icon: <AlertTriangle size={26} /> }
    case 'network':
      return { title: 'Can’t reach the backend', icon: <WifiOff size={26} /> }
    default:
      return { title: 'Scan failed', icon: <AlertTriangle size={26} /> }
  }
}

export function ErrorState({
  error,
  onRetry,
  onNewScan,
}: {
  error: ScanError
  onRetry: () => void
  onNewScan: () => void
}) {
  const { title, icon, hint } = describe(error)

  return (
    <div className="state">
      <div className="state__icon state__icon--error">{icon}</div>
      <h2 className="state__title">{title}</h2>
      <p className="state__message">{error.message}</p>
      <div className="state__actions">
        <button className="btn btn--secondary" onClick={onNewScan}>
          <Plus size={15} />
          New scan
        </button>
        <button className="btn btn--primary" onClick={onRetry}>
          <RotateCcw size={15} />
          Try again
        </button>
      </div>
      {hint && (
        <div className="state__hint">
          <AlertTriangle size={14} />
          {hint}
        </div>
      )}
    </div>
  )
}
