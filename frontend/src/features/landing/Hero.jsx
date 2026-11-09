import Container from '../../components/layout/Container'
import UrlForm from '../scan/UrlForm'
import ScanPendingNotice from '../scan/ScanPendingNotice'
import HeroTerminal from './HeroTerminal'
import { heroChips } from '../../data/landingContent'

export default function Hero({ onScan, submittedUrl }) {
  return (
    <section id="scan" className="relative isolate scroll-mt-16 overflow-hidden">
      <div aria-hidden="true" className="hero-glow absolute inset-0 -z-10" />
      <div aria-hidden="true" className="bg-grid fade-mask absolute inset-0 -z-10" />

      <Container className="grid gap-14 py-16 sm:py-24 lg:grid-cols-[1.1fr_0.9fr] lg:items-center lg:gap-16">
        <div>
          <p className="font-mono text-sm tracking-widest text-accent">
            &gt; DIGITAL TRUST INTELLIGENCE
          </p>

          <h1 className="mt-5 break-words font-display text-3xl leading-[1.15] text-ink sm:text-5xl lg:text-6xl">
            Trust <span className="text-glow text-accent">evidence</span>, not
            appearance.
          </h1>

          <p className="mt-6 max-w-xl text-lg text-ink-muted">
            Paste a link and Veridion examines the URL, domain, certificate,
            reputation and behaviour of the site, then explains what it found,
            why it matters and what to do next.
          </p>

          <div className="mt-8 max-w-xl">
            <UrlForm onSubmit={onScan} />
          </div>

          {submittedUrl && <ScanPendingNotice url={submittedUrl} />}

          <ul aria-label="Analysis layers" className="mt-8 flex flex-wrap gap-2">
            {heroChips.map((chip) => (
              <li
                key={chip}
                className="border border-line px-3 py-1 font-mono text-xs text-ink-muted"
              >
                {chip}
              </li>
            ))}
          </ul>
        </div>

        <HeroTerminal />
      </Container>
    </section>
  )
}