import { useEffect, useState } from 'react'
import Logo from '../brand/Logo'
import Container from './Container'
import { navItems } from '../../data/navigation'
import { useTheme } from '../../hooks/useTheme'

const SUN = [
  '....x....',
  '.x.....x.',
  '..xxxxx..',
  '..xxxxx..',
  'x.xxxxx.x',
  '..xxxxx..',
  '..xxxxx..',
  '.x.....x.',
  '....x....',
]

const MOON = [
  '..xxxx..',
  '.xxx....',
  'xxx.....',
  'xxx.....',
  'xxx.....',
  'xxx.....',
  '.xxx....',
  '..xxxxx.',
]

function PixelIcon({ rows, size = 18 }) {
  const rects = []
  rows.forEach((row, y) =>
    [...row].forEach((ch, x) => {
      if (ch === 'x') rects.push(<rect key={`${x}-${y}`} x={x} y={y} width="1" height="1" />)
    }),
  )
  return (
    <svg
      width={size}
      height={size}
      viewBox={`0 0 ${rows[0].length} ${rows.length}`}
      fill="currentColor"
      shapeRendering="crispEdges"
      aria-hidden="true"
    >
      {rects}
    </svg>
  )
}

function ThemeToggle({ className }) {
  const { theme, toggleTheme } = useTheme()
  const dark = theme === 'dark'
  return (
    <button
      type="button"
      className={`win-btn ${className ?? ''}`}
      onClick={toggleTheme}
      aria-label={dark ? 'Switch to light mode' : 'Switch to dark mode'}
      title={dark ? 'Light mode' : 'Dark mode'}
    >
      <PixelIcon rows={dark ? SUN : MOON} />
    </button>
  )
}

export default function Header() {
  const [menuOpen, setMenuOpen] = useState(false)
  const closeMenu = () => setMenuOpen(false)

  useEffect(() => {
    if (!menuOpen) return undefined
    const onKey = (event) => {
      if (event.key === 'Escape') setMenuOpen(false)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [menuOpen])

  return (
    <header className="sticky top-0 z-50 border-b-2 border-navy bg-surface-raised">
      <Container className="flex h-14 items-center justify-between">
        <Logo />

        <nav aria-label="Primary" className="hidden items-center gap-3 md:flex">
          {navItems.map((item) => (
            <a key={item.id} href={item.href} className="menu-link">
              {item.label}
            </a>
          ))}
          <ThemeToggle />
          <a href="#scan" className="win-btn win-btn-primary">
            Scan URL
          </a>
        </nav>

        <div className="flex items-center gap-2 md:hidden">
          <ThemeToggle />
          <button
            type="button"
            className="win-btn"
            aria-expanded={menuOpen}
            aria-controls="mobile-menu"
            aria-label={menuOpen ? 'Close menu' : 'Open menu'}
            onClick={() => setMenuOpen((open) => !open)}
          >
            <svg
              width="16" height="16" viewBox="0 0 20 20" fill="none"
              stroke="currentColor" strokeWidth="3" shapeRendering="crispEdges"
              aria-hidden="true"
            >
              {menuOpen ? <path d="M4 4L16 16M16 4L4 16" /> : <path d="M2 4H18M2 10H18M2 16H18" />}
            </svg>
          </button>
        </div>
      </Container>

      {menuOpen && (
        <nav
          id="mobile-menu"
          aria-label="Mobile"
          className="border-t-2 border-navy bg-surface-raised md:hidden"
        >
          <Container className="flex flex-col gap-1 py-3">
            {navItems.map((item) => (
              <a key={item.id} href={item.href} onClick={closeMenu} className="menu-link py-3 text-lg">
                {item.label}
              </a>
            ))}
            <a href="#scan" onClick={closeMenu} className="win-btn win-btn-primary mt-2">
              Scan URL
            </a>
          </Container>
        </nav>
      )}
    </header>
  )
}
