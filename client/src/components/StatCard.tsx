import type { ReactNode } from 'react'
import { AnimatedNumber } from './AnimatedNumber'

type Variant = 'default' | 'critical' | 'accent'

export function StatCard({
  icon,
  value,
  label,
  display,
  variant = 'default',
}: {
  icon: ReactNode
  value: number
  label: string
  display?: string
  variant?: Variant
}) {
  const iconClass =
    variant === 'default'
      ? 'stat-card__icon'
      : `stat-card__icon stat-card__icon--${variant}`

  return (
    <div className="stat-card">
      <div className={iconClass}>{icon}</div>
      <div className="stat-card__value">
        {display ?? <AnimatedNumber value={value} />}
      </div>
      <div className="stat-card__label">{label}</div>
    </div>
  )
}
