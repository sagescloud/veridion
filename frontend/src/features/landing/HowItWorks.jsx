import Container from '../../components/layout/Container'
import Panel from '../../components/ui/Panel'
import SectionHeading from '../../components/ui/SectionHeading'
import { howItWorksSteps } from '../../data/landingContent'

export default function HowItWorks() {
  return (
    <section
      id="how-it-works"
      aria-labelledby="how-it-works-title"
      className="scroll-mt-16 border-t border-line py-20 sm:py-28"
    >
      <Container>
        <SectionHeading
          eyebrow="HOW IT WORKS"
          title="From a suspicious link to a clear answer"
          titleId="how-it-works-title"
          description="Four steps, each backed by evidence you can inspect."
        />

        <ol className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {howItWorksSteps.map((step) => (
            <li key={step.id}>
              <Panel className="h-full">
                <p className="font-display text-3xl text-accent">{step.number}</p>
                <h3 className="mt-4 font-display text-lg text-ink">{step.title}</h3>
                <p className="mt-3 text-sm leading-relaxed text-ink-muted">
                  {step.description}
                </p>
              </Panel>
            </li>
          ))}
        </ol>
      </Container>
    </section>
  )
}