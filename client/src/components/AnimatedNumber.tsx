import { useCountUp } from '../hooks/useCountUp'

export function AnimatedNumber({ value }: { value: number }) {
  const display = useCountUp(value)
  return <span style={{ fontVariantNumeric: 'tabular-nums' }}>{display}</span>
}
