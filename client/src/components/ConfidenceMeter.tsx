function bandColor(value: number): string {
  if (value >= 75) return 'var(--success)'
  if (value >= 45) return 'var(--high)'
  return 'var(--low)'
}

export function ConfidenceMeter({
  value,
  label,
  size = 'sm',
}: {
  value: number
  label?: string
  size?: 'sm' | 'lg'
}) {
  return (
    <div
      className={`confidence confidence--${size}`}
      title={`${label ?? ''} confidence — ${value}%`.trim()}
    >
      <div className="confidence__bar">
        <div
          className="confidence__fill"
          style={{ width: `${value}%`, background: bandColor(value) }}
        />
      </div>
      <span className="confidence__pct" style={{ color: bandColor(value) }}>
        {value}%
      </span>
    </div>
  )
}
