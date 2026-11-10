import { useEffect, useRef } from 'react'
import { cn } from '../../utils/cn'
import { useTheme } from '../../hooks/useTheme'
import {
  SCENE_W, SCENE_H, GLOBE_SIZE, GHOST_SIZE, CURSOR_SIZE, WARNING_SIZE,
  drawScene, drawGlobe, drawGhost, drawCursor, drawWarning,
} from './art'

function PixelCanvas({ width, height, draw, theme, className, label }) {
  const ref = useRef(null)

  useEffect(() => {
    const canvas = ref.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    ctx.clearRect(0, 0, width, height)
    ctx.imageSmoothingEnabled = false
    draw(ctx, width, height, theme)
  }, [width, height, draw, theme])

  return (
    <canvas
      ref={ref}
      width={width}
      height={height}
      className={cn('pixel-canvas', className)}
      role={label ? 'img' : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
    />
  )
}

export function PixelScene(props) {
  const { theme } = useTheme()
  return <PixelCanvas width={SCENE_W} height={SCENE_H} draw={drawScene} theme={theme} {...props} />
}

export const PixelGlobe = (props) => (
  <PixelCanvas width={GLOBE_SIZE} height={GLOBE_SIZE} draw={drawGlobe} {...props} />
)
export const PixelGhost = (props) => (
  <PixelCanvas width={GHOST_SIZE[0]} height={GHOST_SIZE[1]} draw={drawGhost} {...props} />
)
export const PixelCursor = (props) => (
  <PixelCanvas width={CURSOR_SIZE[0]} height={CURSOR_SIZE[1]} draw={drawCursor} {...props} />
)
export const PixelWarning = (props) => (
  <PixelCanvas width={WARNING_SIZE[0]} height={WARNING_SIZE[1]} draw={drawWarning} {...props} />
)

export default PixelCanvas
