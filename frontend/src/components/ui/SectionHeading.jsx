import { cn } from '../../utils/cn'

export default function SectionHeading({
  eyebrow,
  title,
  titleId,
  description,
  as: Heading = 'h2',
  className,
}) {
  return (
    <div className={cn('max-w-2xl', className)}>
      {eyebrow && (
        <p className="font-mono text-sm tracking-widest text-accent">{`// ${eyebrow}`}</p>
      )}
      <Heading
        id={titleId}
        className="mt-3 font-display text-2xl leading-tight text-ink sm:text-3xl lg:text-4xl"
      >
        {title}
      </Heading>
      {description && (
        <p className="mt-4 text-lg text-ink-muted">{description}</p>
      )}
    </div>
  )
}