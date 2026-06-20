import { useState } from 'react'
import { Eye, EyeOff, Key, Lock, Plus } from 'lucide-react'

export function Header({
  token,
  onTokenChange,
  repo,
  onNewScan,
  showNewScan,
}: {
  token: string
  onTokenChange: (value: string) => void
  repo?: string
  onNewScan: () => void
  showNewScan: boolean
}) {
  const [show, setShow] = useState(false)

  return (
    <header className="header">
      <div className="header__inner">
        <button className="brand" onClick={onNewScan} aria-label="Go to home">
          <div className="brand__mark">
            <Lock size={16} />
          </div>
          <div className="brand__name">
            <b>SecureVault</b>
            {repo && <span className="brand__repo">{repo}</span>}
          </div>
        </button>

        <div className="header__actions">
          <div className="token-field">
            <Key size={14} />
            <input
              type={show ? 'text' : 'password'}
              value={token}
              onChange={(e) => onTokenChange(e.target.value)}
              placeholder="GitHub token (optional)"
              autoComplete="off"
              spellCheck={false}
              aria-label="GitHub token"
            />
            <button
              type="button"
              className="token-field__toggle"
              onClick={() => setShow((s) => !s)}
              aria-label={show ? 'Hide token' : 'Show token'}
            >
              {show ? <EyeOff size={14} /> : <Eye size={14} />}
            </button>
          </div>

          {showNewScan && (
            <button className="btn btn--secondary" onClick={onNewScan}>
              <Plus size={15} />
              New scan
            </button>
          )}
        </div>
      </div>
    </header>
  )
}
