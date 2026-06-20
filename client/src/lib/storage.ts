// Persists the remediation checklist (which findings the user has ticked off)
// per repository, across refreshes.

export type ChecklistState = Record<string, boolean>

const keyFor = (repo: string) => `securevault:checklist:${repo}`

export function loadChecklist(repo: string): ChecklistState {
  try {
    const raw = localStorage.getItem(keyFor(repo))
    return raw ? (JSON.parse(raw) as ChecklistState) : {}
  } catch {
    return {}
  }
}

export function saveChecklist(repo: string, state: ChecklistState): void {
  try {
    localStorage.setItem(keyFor(repo), JSON.stringify(state))
  } catch {
    /* storage unavailable (private mode / quota) — degrade gracefully */
  }
}
