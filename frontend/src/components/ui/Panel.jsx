import { cn } from '../../utils/cn'

const TONES = {
  default: 'bg-surface',
  raised: 'bg-surface-raised',
}

export default function Panel({
  as: Component = 'div',
  tone = 'default',
  className,
  children,
  ...props
}) {
  return (
    <Component
      className={cn('border border-line p-6', TONES[tone], className)}
      {...props}
    >
      {children}
    </Component>
  )
}