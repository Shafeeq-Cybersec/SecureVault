// owner/repo or a github.com URL. Mirrors the backend's parser.
const TARGET_RE =
  /^(?:https?:\/\/)?(?:www\.)?(?:github\.com\/)?[\w.-]+\/[\w.-]+?(?:\.git)?\/?$/

export function isValidTarget(value: string): boolean {
  return TARGET_RE.test(value.trim())
}

/** Normalize any accepted form to "owner/repo" for display. */
export function normalizeTarget(value: string): string {
  const m = value
    .trim()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .replace(/^github\.com\//, '')
    .replace(/\.git$/, '')
    .replace(/\/$/, '')
  return m
}
