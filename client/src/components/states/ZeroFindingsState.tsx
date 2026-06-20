import { Download, FileSearch, Plus, ShieldCheck } from 'lucide-react'
import type { ScanResult } from '../../types'
import { downloadReport } from '../../lib/export'

export function ZeroFindingsState({
  result,
  onNewScan,
}: {
  result: ScanResult
  onNewScan: () => void
}) {
  return (
    <div className="state fade-in">
      <div className="state__icon state__icon--success">
        <ShieldCheck size={28} />
      </div>
      <h2 className="state__title">No secrets found</h2>
      <p className="state__message">
        SecureVault scanned <code>{result.repository}</code> and found no exposed
        credentials. Clean repository.
      </p>
      <div className="state__actions">
        <button className="btn btn--secondary" onClick={() => downloadReport(result)}>
          <Download size={15} />
          Export report
        </button>
        <button className="btn btn--primary" onClick={onNewScan}>
          <Plus size={15} />
          Scan another
        </button>
      </div>
      <div className="state__hint">
        <FileSearch size={14} />
        {result.files_scanned} files scanned · {result.files_skipped} skipped ·
        branch {result.branch}
      </div>
    </div>
  )
}
