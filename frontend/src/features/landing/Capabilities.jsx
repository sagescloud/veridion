import Container from '../../components/layout/Container'
import Panel from '../../components/ui/Panel'
import SectionHeading from '../../components/ui/SectionHeading'
import { capabilities } from '../../data/landingContent'

export default function Capabilities() {
  return (
    <section
      id="capabilities"
      aria-labelledby="capabilities-title"
      className="scroll-mt-16 border-t border-line bg-surface/40 py-20 sm:py-28"
    >
      <Container>
        <SectionHeading
          eyebrow="CAPABILITIES"
          title="Multiple layers, one explainable assessment"
          titleId="capabilities-title"
          description="Independent checks that each contribute to the final result, and each say clearly when they could not run."
        />

        <ul className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {capabilities.map((capability) => (
            <li key={capability.id}>
              <Panel className="h-full transition-colors hover:border-accent/60">
                <div className="flex items-center justify-between font-mono text-xs tracking-widest">
                  <span className="text-accent">{capability.number}</span>
                  <span className="text-ink-faint">{capability.tag}</span>
                </div>
                <h3 className="mt-5 font-display text-lg text-ink">
                  {capability.title}
                </h3>
                <p className="mt-3 text-sm leading-relaxed text-ink-muted">
                  {capability.description}
                </p>
              </Panel>
            </li>
          ))}
        </ul>
      </Container>
    </section>
  )
}