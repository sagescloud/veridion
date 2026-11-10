import RetroWindow from '../../components/ui/RetroWindow'
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
    <figure className={cn('relative m-0', className)}>
      <RetroWindow as="div" title="sample_report.txt" aria-hidden="true">
        <div className="space-y-4 p-4 font-mono text-[13px]">
          <p className="animate-reveal text-cobalt motion-reduce:animate-none" style={revealStyle(0)}>
            <span className="text-ink-faint">$ </span>
            {command}
          </p>

          <ul className="space-y-2">
            {findings.map((finding, index) => (
              <li
                key={finding.id}
                className="grid animate-reveal grid-cols-[2.75rem_1fr] gap-x-2 motion-reduce:animate-none"
                style={revealStyle(index + 1)}
              >
                <span className={cn('font-bold', TONE_CLASSES[finding.tone])}>{finding.tag}</span>
                <span className="text-ink">
                  <span className="text-ink-muted">{finding.label}</span> {finding.text}
                </span>
              </li>
            ))}
          </ul>

          <p
            className="animate-reveal border-t-2 border-dashed border-line-strong pt-4 text-ink motion-reduce:animate-none"
            style={revealStyle(findings.length + 1)}
          >
            RISK <span className="font-bold text-risk-high">{summary.score}/100</span>
            {' · '}
            {summary.classification}
            {' · '}
            CONFIDENCE {summary.confidence}
          </p>

          <p className="animate-reveal text-ink-muted motion-reduce:animate-none" style={revealStyle(findings.length + 2)}>
            <span className="text-cobalt">&gt; </span>
            {note}
            <span className="ml-1 inline-block h-4 w-2 translate-y-[3px] animate-blink bg-cobalt motion-reduce:animate-none" />
          </p>
        </div>
      </RetroWindow>

      <figcaption className="mt-3 inline-block border-2 border-navy bg-surface px-2 py-1 font-mono text-xs text-ink-muted">
        Illustrative example only. This is not a real scan result.
      </figcaption>
    </figure>
  )
}
