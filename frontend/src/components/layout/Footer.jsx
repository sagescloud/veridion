import Logo from '../brand/Logo'
import Container from './Container'

export default function Footer() {
  return (
    <footer className="border-t border-line bg-surface">
      <Container className="flex flex-col gap-8 py-10 md:flex-row md:items-start md:justify-between">
        <div className="max-w-sm">
          <Logo />
          <p className="mt-3 text-sm text-ink-muted">
            Trust should be established through evidence, not appearance.
          </p>
        </div>

        <div className="max-w-md text-sm text-ink-muted">
          <p>
            No scan can guarantee that a website is safe. An absence of findings
            is not proof of safety.
          </p>
          <p className="mt-3 font-mono text-xs text-ink-faint">
            Built for HackMatrix &apos;26.
          </p>
        </div>
      </Container>
    </footer>
  )
}