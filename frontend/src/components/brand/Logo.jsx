import { Link } from 'react-router-dom'
import { cn } from '../../utils/cn'

export default function Logo({ className }) {
  return (
    <Link
      to="/"
      aria-label="Veridion home"
      className={cn(
        'inline-flex items-center gap-1 font-display text-xl tracking-widest text-ink',
        className,
      )}
    >
      VERIDION
      <span
        aria-hidden="true"
        className="inline-block h-4 w-2 translate-y-[2px] animate-blink bg-accent motion-reduce:animate-none"
      />
    </Link>
  )
}
