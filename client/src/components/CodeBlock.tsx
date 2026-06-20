import { useMemo } from 'react'
import Prism from 'prismjs'
import 'prismjs/components/prism-clike'
import 'prismjs/components/prism-javascript'
import 'prismjs/components/prism-typescript'
import 'prismjs/components/prism-python'
import 'prismjs/components/prism-json'
import 'prismjs/components/prism-bash'
import 'prismjs/components/prism-yaml'
import { FileCode } from 'lucide-react'
import { CopyButton } from './CopyButton'

const EXT_LANG: Record<string, string> = {
  js: 'javascript',
  jsx: 'javascript',
  mjs: 'javascript',
  cjs: 'javascript',
  ts: 'typescript',
  tsx: 'typescript',
  py: 'python',
  json: 'json',
  sh: 'bash',
  bash: 'bash',
  zsh: 'bash',
  yml: 'yaml',
  yaml: 'yaml',
}

function langFor(path: string): string {
  const base = path.split('/').pop()?.toLowerCase() ?? ''
  if (base.startsWith('.env') || base === 'dockerfile') return 'bash'
  const ext = base.includes('.') ? base.split('.').pop()! : ''
  return EXT_LANG[ext] ?? ''
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

export function CodeBlock({
  code,
  filePath,
  lineNumber,
}: {
  code: string
  filePath: string
  lineNumber: number
}) {
  const lang = langFor(filePath)
  const html = useMemo(() => {
    if (lang && Prism.languages[lang]) {
      return Prism.highlight(code, Prism.languages[lang], lang)
    }
    return escapeHtml(code)
  }, [code, lang])

  return (
    <div className="code-block">
      <div className="code-block__bar">
        <div className="code-block__file">
          <FileCode size={13} />
          <span>{filePath}</span>
        </div>
        <CopyButton text={filePath} label="Copy path" />
      </div>
      <pre>
        <code className={lang ? `language-${lang}` : ''}>
          <span className="code-block__ln">{lineNumber}</span>
          <span dangerouslySetInnerHTML={{ __html: html }} />
        </code>
      </pre>
    </div>
  )
}
