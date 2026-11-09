import { terminalSample } from '../../data/landingContent'
import { cn } from '../../utils/cn'

const TONE_CLASSES = {
  high: 'text-risk-high',
  moderate: 'text-risk-moderate',
  muted: 'text-ink-muted',
}

const START_DELAY_MS = 400
const LINE_DELAY_MS = 350

export default function HeroTerminal({ className }) {
  const { command, findings, summary, note } = terminalSample

  const revealStyle = (index) => ({
    animationDelay: `${START_DELAY_MS + index * LINE_DELAY_MS}ms`,
  })

  return (
    <figure className={cn('m-0', className)}>
      <div
        aria-hidden="true"
        className="scanlines relative overflow-hidden border-2 border-line-strong bg-surface shadow-glow"
      >
        <div className="flex items-center justify-between border-b border-line-strong bg-surface-raised px-4 py-2">
          <div className="flex gap-1.5">
            <span className="h-2.5 w-2.5 bg-line-strong" />
            <span className="h-2.5 w-2.5 bg-line-strong" />
            <span className="h-2.5 w-2.5 bg-accent" />
          </div>
          <span className="font-mono text-xs tracking-widest text-ink-faint">
            SAMPLE OUTPUT
          </span>
        </div>

        <div className="space-y-4 p-5 font-mono text-sm">
          <p
            className="animate-reveal text-accent motion-reduce:animate-none"
            style={revealStyle(0)}
          >
            <span className="text-ink-faint">$ </span>
            {command}
          </p>

          <ul className="space-y-2">
            {findings.map((finding, index) => (
              <li
                key={finding.id}
                className="grid animate-reveal grid-cols-[3rem_1fr] gap-x-3 motion-reduce:animate-none"
                style={revealStyle(index + 1)}
              >
                <span className={cn('font-bold', TONE_CLASSES[finding.tone])}>
                  {finding.tag}
                </span>
                <span className="text-ink">
                  <span className="text-ink-muted">{finding.label}</span>{' '}
                  {finding.text}
                </span>
              </li>
            ))}
          </ul>

          <p
            className="animate-reveal border-t border-line-strong pt-4 text-ink motion-reduce:animate-none"
            style={revealStyle(findings.length + 1)}
          >
            RISK{' '}
            <span className="font-bold text-risk-high">{summary.score}/100</span>
            {' · '}
            {summary.classification}
            {' · '}
            CONFIDENCE {summary.confidence}
          </p>

          <p
            className="animate-reveal text-ink-muted motion-reduce:animate-none"
            style={revealStyle(findings.length + 2)}
          >
            <span className="text-accent">&gt; </span>
            {note}
            <span className="ml-1 inline-block h-4 w-2 translate-y-[3px] animate-blink bg-accent motion-reduce:animate-none" />
          </p>
        </div>
      </div>

      <figcaption className="mt-3 font-mono text-xs text-ink-faint">
        Illustrative example only. This is not a real scan result.
      </figcaption>
    </figure>
  )
}