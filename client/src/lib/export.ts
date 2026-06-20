import type { ScanResult } from '../types'

/** Build a formatted JSON report and trigger a browser download. */
export function downloadReport(result: ScanResult): void {
  const report = {
    tool: 'SecureVault',
    generated_at: new Date().toISOString(),
    repository: result.repository,
    branch: result.branch,
    scanned_at: result.scanned_at,
    summary: {
      total_findings: result.total_findings,
      by_severity: result.severity_counts,
      files_scanned: result.files_scanned,
      files_skipped: result.files_skipped,
      partial: result.partial,
    },
    findings: result.findings.map((f) => ({
      severity: f.severity,
      type: f.secret_type,
      file: f.file_path,
      line: f.line_number,
      preview: f.match_preview,
      remediation: f.remediation,
    })),
    warnings: result.errors,
  }

  const blob = new Blob([JSON.stringify(report, null, 2)], {
    type: 'application/json',
  })
  const url = URL.createObjectURL(blob)
  const date = new Date().toISOString().slice(0, 10)
  const safeRepo = result.repository.replace('/', '-')

  const a = document.createElement('a')
  a.href = url
  a.download = `securevault-${safeRepo}-${date}.json`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}
