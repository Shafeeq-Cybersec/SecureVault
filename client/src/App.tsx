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
          <span>Built by <a href="https://github.com/Shafeeq-Cybersec" target="_blank" rel="noopener noreferrer">Shafeeq S</a></span>
          <span>SecureVault — GitHub Secrets Scanner</span>
        </div>
      </footer>
    </div>
  )
}

export default App
