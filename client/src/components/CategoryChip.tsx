import { isRealCategory } from '../types'

export function CategoryChip({ category }: { category: string }) {
  const real = isRealCategory(category)
  return (
    <span className={`cat-chip${real ? ' cat-chip--real' : ' cat-chip--benign'}`}>
      {category}
    </span>
  )
}
