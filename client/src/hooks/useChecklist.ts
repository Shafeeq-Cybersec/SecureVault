import { useCallback, useEffect, useState } from 'react'
import { loadChecklist, saveChecklist, type ChecklistState } from '../lib/storage'

/** Remediation checklist state, persisted to localStorage per repository. */
export function useChecklist(repo: string | null) {
  const [checked, setChecked] = useState<ChecklistState>({})

  useEffect(() => {
    setChecked(repo ? loadChecklist(repo) : {})
  }, [repo])

  const toggle = useCallback(
    (key: string) => {
      setChecked((prev) => {
        const next = { ...prev, [key]: !prev[key] }
        if (repo) saveChecklist(repo, next)
        return next
      })
    },
    [repo],
  )

  const isChecked = useCallback((key: string) => !!checked[key], [checked])

  return { checked, toggle, isChecked }
}
