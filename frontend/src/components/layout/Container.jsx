import { cn } from '../../utils/cn'

export default function Container({
  as: Component = 'div',
  className,
  children,
  ...props
}) {
  return (
    <Component
      className={cn('mx-auto w-full max-w-6xl px-4 sm:px-6 lg:px-8', className)}
      {...props}
    >
      {children}
    </Component>
  )
}