import { useCallback, useState } from 'react'
import { scanRepo } from './api'
import { normalizeTarget } from './lib/validate'
import { useChecklist } from './hooks/useChecklist'
import type { ScanError, ScanResult } from './types'
import { Header } from './components/Header'
import { HeroInput } from './components/HeroInput'
import { Results } from './components/Results'
import { LoadingState } from './components/states/LoadingState'
import { ErrorState } from './components/states/ErrorState'
import { ZeroFindingsState } from './components/states/ZeroFindingsState'
type Status = 'idle' | 'scanning' | 'results' | 'error'

function App() {
  const [token, setToken] = useState('')
  const [target, setTarget] = useState('')
  const [status, setStatus] = useState<Status>('idle')
  const [result, setResult] = useState<ScanResult | null>(null)
  const [error, setError] = useState<ScanError | null>(null)
  const [elapsedMs, setElapsedMs] = useState(0)
  const [scanRepoName, setScanRepoName] = useState('')

  const { isChecked, toggle } = useChecklist(result ? result.repository : null)

  const runScan = useCallback(
    async (t: string) => {
      setTarget(t)
      setScanRepoName(normalizeTarget(t))
      setStatus('scanning')
      setError(null)
      const start = performance.now()
      try {
        const res = await scanRepo(t, token)
        setElapsedMs(performance.now() - start)
        setResult(res)
        setStatus('results')
      } catch (e) {
        setError(e as ScanError)
        setStatus('error')
      }
    },
    [token],
  )

  const newScan = useCallback(() => {
    setStatus('idle')
    setResult(null)
    setError(null)
  }, [])

  const retry = useCallback(() => {
    if (target) runScan(target)
  }, [target, runScan])

  const hasFindings = !!result && result.total_findings > 0

  return (
    <div className="app-shell">
      <Header
        token={token}
        onTokenChange={setToken}
        repo={status !== 'idle' ? scanRepoName : undefined}
        onNewScan={newScan}
        showNewScan={status !== 'idle'}
      />

      {status === 'idle' && (
        <HeroInput target={target} onTargetChange={setTarget} onScan={runScan} />
      )}

      {status === 'scanning' && <LoadingState repo={scanRepoName} />}

      {status === 'error' && error && (
        <ErrorState error={error} onRetry={retry} onNewScan={newScan} />
      )}

      {status === 'results' && result && !hasFindings && (
        <ZeroFindingsState result={result} onNewScan={newScan} />
      )}

      {status === 'results' && result && hasFindings && (
        <Results
          result={result}
          elapsedMs={elapsedMs}
          isFixed={isChecked}
          onToggleFixed={toggle}
        />
      )}

      <footer className="footer">
        <div className="footer__inner">
          <div className="footer__left">
            <span>Built by <a href="https://github.com/Shafeeq-Cybersec" target="_blank" rel="noopener noreferrer">Shafeeq S</a></span>
            <a href="https://github.com/Shafeeq-Cybersec" target="_blank" rel="noopener noreferrer" title="GitHub" className="footer__icon-btn" aria-label="GitHub">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v 3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
              </svg>
            </a>
            <a href="https://www.linkedin.com/in/shafeeq-cybersec/" target="_blank" rel="noopener noreferrer" title="LinkedIn" className="footer__icon-btn" aria-label="LinkedIn">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M16 8a6 6 0 016 6v7h-4v-7a2 2 0 00-2-2 2 2 0 00-2 2v7h-4v-7a6 6 0 016-6zM2 9h4v12H2z"/><circle cx="4" cy="4" r="2"/>
              </svg>
            </a>
          </div>
          <span className="footer__right">SecureVault | GitHub Secrets Scanner</span>
        </div>
      </footer>
    </div>
  )
}

export default App
