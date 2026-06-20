import { AlertOctagon, Clock, FileSearch, ShieldAlert } from 'lucide-react'
import type { ScanResult } from '../types'
import { StatCard } from './StatCard'

function formatTime(ms: number): string {
  const s = ms / 1000
  if (s < 10) return `${s.toFixed(1)}s`
  if (s < 60) return `${Math.round(s)}s`
  return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`
}

export function SummaryCards({
  result,
  elapsedMs,
}: {
  result: ScanResult
  elapsedMs: number
}) {
  return (
    <div className="summary-cards">
      <StatCard
        icon={<ShieldAlert size={16} />}
        value={result.total_findings}
        label="Secrets found"
      />
      <StatCard
        icon={<AlertOctagon size={16} />}
        value={result.severity_counts.CRITICAL}
        label="Critical"
        variant="critical"
      />
      <StatCard
        icon={<FileSearch size={16} />}
        value={result.files_scanned}
        label="Files scanned"
      />
      <StatCard
        icon={<Clock size={16} />}
        value={0}
        display={formatTime(elapsedMs)}
        label="Scan time"
        variant="accent"
      />
    </div>
  )
}
