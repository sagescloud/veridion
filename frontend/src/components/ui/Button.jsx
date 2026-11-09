import { cn } from '../../utils/cn'

const BASE =
  'inline-flex select-none items-center justify-center gap-2 border-2 font-display uppercase tracking-wider transition-[transform,box-shadow,background-color,border-color,color] duration-100 disabled:cursor-not-allowed disabled:opacity-50'

const VARIANTS = {
  primary:
    'border-accent bg-accent text-canvas shadow-pixel hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-pixel-sm active:translate-x-[4px] active:translate-y-[4px] active:shadow-none',
  secondary:
    'border-accent/60 bg-transparent text-accent hover:border-accent hover:bg-accent/10',
  ghost:
    'border-transparent bg-transparent text-ink-muted hover:text-accent',
}

const SIZES = {
  sm: 'h-10 px-4 text-xs',
  md: 'h-12 px-6 text-sm',
  lg: 'h-14 px-8 text-base',
}

export default function Button({
  variant = 'primary',
  size = 'md',
  href,
  type = 'button',
  className,
  children,
  ...props
}) {
  const classes = cn(BASE, VARIANTS[variant], SIZES[size], className)

  if (href) {
    return (
      <a href={href} className={classes} {...props}>
        {children}
      </a>
    )
  }

  return (
    <button type={type} className={classes} {...props}>
      {children}
    </button>
  )
}