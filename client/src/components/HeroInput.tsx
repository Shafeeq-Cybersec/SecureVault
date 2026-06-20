import { useState } from 'react'
import { AlertCircle, Check, FolderGit2, Search, ShieldCheck } from 'lucide-react'
import { isValidTarget } from '../lib/validate'

const EXAMPLES = ['octocat/Hello-World', 'gitleaks/gitleaks']

export function HeroInput({
  target,
  onTargetChange,
  onScan,
}: {
  target: string
  onTargetChange: (value: string) => void
  onScan: (target: string) => void
}) {
  const [touched, setTouched] = useState(false)
  const trimmed = target.trim()
  const valid = trimmed.length > 0 && isValidTarget(trimmed)
  const showError = touched && trimmed.length > 0 && !valid

  const fieldClass = `repo-field${valid && touched ? ' repo-field--valid' : ''}${
    showError ? ' repo-field--invalid' : ''
  }`

  const submit = () => {
    if (valid) onScan(trimmed)
  }

  return (
    <div className="hero">
      <div className="hero__inner">
        <div className="hero__eyebrow">
          <ShieldCheck size={13} />
          GitHub secrets scanner
        </div>
        <h1 className="hero__title">
          Find secrets before
          <br />
          attackers do.
        </h1>
        <p className="hero__subtitle">
          Scan any public GitHub repository for committed API keys, tokens, and credentials. In seconds.
        </p>

        <div className="hero__row">
          <div className={fieldClass}>
            <span className="repo-field__prefix">
              <FolderGit2 size={20} />
            </span>
            <input
              value={target}
              onChange={(e) => onTargetChange(e.target.value)}
              onBlur={() => setTouched(true)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') submit()
              }}
              placeholder="owner/repository"
              autoFocus
              spellCheck={false}
              autoComplete="off"
              aria-label="Repository"
            />
            <span
              className={`repo-field__status${
                valid ? ' repo-field__status--valid' : ''
              }${showError ? ' repo-field__status--invalid' : ''}`}
            >
              {valid ? (
                <Check size={18} />
              ) : showError ? (
                <AlertCircle size={18} />
              ) : null}
            </span>
          </div>
          <button
            className="btn btn--primary btn--lg"
            disabled={!valid}
            onClick={submit}
          >
            <Search size={16} />
            Scan
          </button>
        </div>

        <div className="hero__error">
          {showError && (
            <>
              <AlertCircle size={14} />
              Enter a valid repo like <b>&nbsp;owner/repo&nbsp;</b> or a github.com
              URL
            </>
          )}
        </div>

        <div className="hero__examples">
          <span className="hero__examples-label">Try</span>
          {EXAMPLES.map((ex) => (
            <button
              key={ex}
              className="example-chip"
              onClick={() => {
                onTargetChange(ex)
                setTouched(true)
              }}
            >
              {ex}
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}
