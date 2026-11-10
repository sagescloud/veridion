import { Link } from 'react-router-dom'
import { PixelGhost } from '../pixel/PixelCanvas'
import { cn } from '../../utils/cn'

export default function Logo({ className }) {
  return (
    <Link
      to="/"
      aria-label="Veridion home"
      className={cn('inline-flex items-center gap-2.5', className)}
    >
      <PixelGhost className="w-6" />
      <span className="font-pixel text-xl font-bold uppercase tracking-wide text-cobalt">
        Veridion
      </span>
    </Link>
  )
}
