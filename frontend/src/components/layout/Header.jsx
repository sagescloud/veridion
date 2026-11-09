import { useEffect, useState } from 'react'
import Logo from '../brand/Logo'
import Button from '../ui/Button'
import Container from './Container'
import { navItems } from '../../data/navigation'

export default function Header() {
  const [menuOpen, setMenuOpen] = useState(false)

  const closeMenu = () => setMenuOpen(false)

  useEffect(() => {
    if (!menuOpen) return undefined

    const handleKeyDown = (event) => {
      if (event.key === 'Escape') setMenuOpen(false)
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [menuOpen])

  return (
    <header className="sticky top-0 z-50 border-b border-line bg-canvas/85 backdrop-blur">
      <Container className="flex h-16 items-center justify-between">
        <Logo />

        <nav aria-label="Primary" className="hidden items-center gap-8 md:flex">
          {navItems.map((item) => (
            <a
              key={item.id}
              href={item.href}
              className="font-mono text-sm text-ink-muted transition-colors hover:text-accent"
            >
              {item.label}
            </a>
          ))}
          <Button href="#scan" size="sm">
            Scan URL
          </Button>
        </nav>

        <button
          type="button"
          className="inline-flex h-10 w-10 items-center justify-center border-2 border-line-strong text-ink transition-colors hover:border-accent hover:text-accent md:hidden"
          aria-expanded={menuOpen}
          aria-controls="mobile-menu"
          aria-label={menuOpen ? 'Close menu' : 'Open menu'}
          onClick={() => setMenuOpen((open) => !open)}
        >
          <svg
            width="20"
            height="20"
            viewBox="0 0 20 20"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="square"
            aria-hidden="true"
          >
            {menuOpen ? (
              <path d="M4 4L16 16M16 4L4 16" />
            ) : (
              <path d="M3 5H17M3 10H17M3 15H17" />
            )}
          </svg>
        </button>
      </Container>

      {menuOpen && (
        <nav
          id="mobile-menu"
          aria-label="Mobile"
          className="border-t border-line bg-canvas md:hidden"
        >
          <Container className="flex flex-col gap-1 py-4">
            {navItems.map((item) => (
              <a
                key={item.id}
                href={item.href}
                onClick={closeMenu}
                className="py-3 font-mono text-base text-ink-muted transition-colors hover:text-accent"
              >
                {item.label}
              </a>
            ))}
            <Button href="#scan" onClick={closeMenu} className="mt-3">
              Scan URL
            </Button>
          </Container>
        </nav>
      )}
    </header>
  )
}