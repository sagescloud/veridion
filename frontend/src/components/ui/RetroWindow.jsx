import { cn } from '../../utils/cn'

const ctlProps = {
  width: 10,
  height: 10,
  viewBox: '0 0 10 10',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 2,
  shapeRendering: 'crispEdges',
  'aria-hidden': true,
}

export default function RetroWindow({
  title,
  titleId,
  as: Component = 'section',
  className,
  bodyClassName,
  children,
  ...props
}) {
  return (
    <Component className={cn('win', className)} {...props}>
      <div className="win-titlebar">
        <span id={titleId} className="win-title truncate">
          {title}
        </span>
        <span aria-hidden="true" className="win-controls">
          <span className="win-ctl">
            <svg {...ctlProps}><path d="M1 8H7" /></svg>
          </span>
          <span className="win-ctl">
            <svg {...ctlProps}><rect x="1" y="1" width="8" height="8" /></svg>
          </span>
          <span className="win-ctl">
            <svg {...ctlProps}><path d="M2 2L8 8M8 2L2 8" /></svg>
          </span>
        </span>
      </div>
      <div className={cn('win-body', bodyClassName)}>{children}</div>
    </Component>
  )
}
