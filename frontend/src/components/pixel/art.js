// All pixel art is drawn procedurally onto tiny canvases and scaled up with
// image-rendering: pixelated. No image files, no gradients.

export const SCENE_W = 192
export const SCENE_H = 108
export const GLOBE_SIZE = 40

const px = (ctx, x, y, color, w = 1, h = 1) => {
  ctx.fillStyle = color
  ctx.fillRect(x, y, w, h)
}

// Deterministic RNG so the landscape is identical on every load (mulberry32)
function rng(seed) {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const PALETTES = {
  light: {
    sky: ['#b9d8c4', '#c6e1cb', '#d3e8cf', '#e0eed3', '#edf3dc'],
    sun: ['#f3efc9', '#fbf8e1'],
    cloud: { top: '#fbfaf2', mid: '#f6f8ee', shade: '#e0ece0' },
    bird: '#4a6b8a',
    farLit: '#a8c4cf', farShade: '#8fb0be',
    snowLit: '#f6f7ef', snowShade: '#dfe8ea', farHaze: '#d9e8d2',
    midLit: '#8cbc98', midShade: '#6fa07e', midHaze: '#a9cfa6',
    hill: { hi: '#c0e3ad', top: '#a2cf92', base: '#8dbd80' },
    pine: { light: '#5a9a6e', dark: '#2d5240', mid: '#3c6b50', speck: '#4a8060', trunk: '#5b4b3b' },
    meadow: { hi: '#cbe8b6', a: '#b1da9f', base: '#a6d494', speck: '#9fcf8d' },
    petals: ['#e9a9b8', '#fffdf5', '#f3e2a0'],
    tuft: '#6aa56e',
    night: false,
  },
  dark: {
    sky: ['#0c211c', '#10291f', '#143225', '#193b2c', '#1f4533'],
    sun: ['#d9e3c4', '#f1f5df'],
    cloud: { top: '#3a6552', mid: '#335c4a', shade: '#2a4d3d' },
    bird: '#86b49a',
    farLit: '#3b6f6f', farShade: '#2f5b5e',
    snowLit: '#bcd3cf', snowShade: '#8fb0ae', farHaze: '#1f4533',
    midLit: '#2f6b4c', midShade: '#245540', midHaze: '#2a5a43',
    hill: { hi: '#4a9a63', top: '#3a8553', base: '#2f7045' },
    pine: { light: '#3f8a5c', dark: '#12301f', mid: '#1d4a32', speck: '#265a3c', trunk: '#3a2e24' },
    meadow: { hi: '#6fb878', a: '#4d9c5f', base: '#43895a', speck: '#3a7b50' },
    petals: ['#e9a9b8', '#f3e2a0', '#cfe9d6'],
    tuft: '#2a6a44',
    night: true,
  },
}

function fillDisc(ctx, cx, cy, r, color) {
  for (let y = -r; y <= r; y++)
    for (let x = -r; x <= r; x++)
      if (x * x + y * y <= r * r) px(ctx, cx + x, cy + y, color)
}

function ellipse(ctx, cx, cy, rx, ry, pick) {
  for (let y = -ry; y <= ry; y++)
    for (let x = -rx; x <= rx; x++)
      if ((x * x) / (rx * rx) + (y * y) / (ry * ry) <= 1)
        px(ctx, cx + x, cy + y, pick(cx + x, cy + y, y, ry))
}

function cloud(ctx, x, y, s, c) {
  const blobs = [[0, 0, 10, 4], [-9, 2, 7, 3], [10, 2, 8, 3], [3, -3, 6, 3]]
  for (const [dx, dy, rx, ry] of blobs) {
    ellipse(ctx, x + dx * s, y + dy * s, rx * s, ry * s, (ax, ay, ly, r) =>
      ly > r * 0.25 ? ((ax + ay) % 2 === 0 ? c.shade : c.mid) : c.top,
    )
  }
}

function bird(ctx, x, y, c) {
  px(ctx, x, y, c)
  px(ctx, x + 1, y + 1, c)
  px(ctx, x + 2, y, c)
  px(ctx, x + 3, y + 1, c)
  px(ctx, x + 4, y, c)
}

function pine(ctx, x, base, height, c) {
  const top = base - height
  for (let i = 0; i < height; i++) {
    const tier = Math.floor(i / 4)
    const j = i % 4
    const hw = Math.floor(tier * 0.8 + j * 0.75)
    const y = top + i
    for (let dx = -hw; dx <= hw; dx++) {
      let col = (x + dx + y) % 5 === 0 ? c.speck : c.mid
      if (hw > 0 && dx === -hw) col = c.light
      if (hw > 0 && dx === hw) col = c.dark
      px(ctx, x + dx, y, col)
    }
  }
  px(ctx, x, base, c.trunk, 1, 3)
}

export function drawScene(ctx, w, h, theme = 'light') {
  const P = PALETTES[theme] ?? PALETTES.light
  const rand = rng(26)
  const horizon = 66
  const SKY = P.sky

  // Sky: stepped bands with checkerboard dithering at the seams
  for (let y = 0; y < horizon; y++) {
    const t = (y / horizon) * SKY.length
    const base = Math.min(SKY.length - 1, Math.floor(t))
    const frac = t - Math.floor(t)
    for (let x = 0; x < w; x++) {
      let i = base
      if (frac > 0.7 && i < SKY.length - 1 && (x + y) % 2 === 0) i += 1
      px(ctx, x, y, SKY[i])
    }
  }

  // Night: stars (own RNG so tree layout is identical in both themes)
  if (P.night) {
    const starRand = rng(7)
    for (let i = 0; i < 46; i++) {
      const x = Math.floor(starRand() * w)
      const y = Math.floor(starRand() * 50)
      const bright = starRand() > 0.6
      px(ctx, x, y, bright ? '#f1f5df' : '#9fc3a8')
      if (bright && starRand() > 0.6) {
        px(ctx, x - 1, y, '#9fc3a8')
        px(ctx, x + 1, y, '#9fc3a8')
        px(ctx, x, y - 1, '#9fc3a8')
        px(ctx, x, y + 1, '#9fc3a8')
      }
    }
  }

  // Sun / moon
  fillDisc(ctx, 152, 18, 9, P.sun[0])
  fillDisc(ctx, 152, 18, 6, P.sun[1])
  if (P.night) {
    px(ctx, 149, 16, '#c9d5b3', 2, 2)
    px(ctx, 154, 20, '#c9d5b3', 2, 1)
    px(ctx, 151, 22, '#c9d5b3', 1, 1)
  }

  cloud(ctx, 26, 16, 1, P.cloud)
  cloud(ctx, 88, 32, 1, P.cloud)
  cloud(ctx, 118, 10, 2, P.cloud)
  cloud(ctx, 168, 40, 1, P.cloud)

  bird(ctx, 60, 14, P.bird)
  bird(ctx, 72, 20, P.bird)
  bird(ctx, 66, 25, P.bird)

  // Far mountains
  const far = (x) =>
    Math.round(44 - 10 * Math.sin(x * 0.035 + 0.8) - 6 * Math.sin(x * 0.09 + 2.1) - 3 * Math.sin(x * 0.23))
  for (let x = 0; x < w; x++) {
    const top = far(x)
    const slope = far(x + 2) - far(x - 2)
    const shaded = slope > 0 || (slope === 0 && x % 2 === 0)
    for (let y = top; y < 80; y++) {
      let c = shaded ? P.farShade : P.farLit
      if (top < 34 && y - top < 2 + ((x * 7) % 3)) c = shaded ? P.snowShade : P.snowLit
      else if (y > 58 && (x + y) % 2 === 0) c = P.farHaze
      px(ctx, x, y, c)
    }
  }

  // Mid mountains
  const mid = (x) =>
    Math.round(60 - 8 * Math.sin(x * 0.05 + 3.3) - 5 * Math.sin(x * 0.13 + 0.4) - 2 * Math.sin(x * 0.3))
  for (let x = 0; x < w; x++) {
    const top = mid(x)
    const slope = mid(x + 2) - mid(x - 2)
    const shaded = slope > 0 || (slope === 0 && x % 2 === 0)
    for (let y = top; y < 88; y++) {
      let c = shaded ? P.midShade : P.midLit
      if (y > 72 && (x + y) % 2 === 0) c = P.midHaze
      px(ctx, x, y, c)
    }
  }

  // Rolling hills
  const hill1 = (x) => Math.round(74 + 3 * Math.sin(x * 0.06 + 1) + 2 * Math.sin(x * 0.17))
  for (let x = 0; x < w; x++) {
    const top = hill1(x)
    for (let y = top; y < h; y++) {
      const d = y - top
      let c = P.hill.base
      if (d === 0) c = P.hill.hi
      else if (d < 4) c = P.hill.top
      else if (d < 6 && (x + y) % 2 === 0) c = P.hill.top
      px(ctx, x, y, c)
    }
  }

  // Pine forest, denser at the edges so the centre stays open
  const trees = []
  for (let i = 0; i < 34; i++) {
    const r = rand()
    const x = Math.floor(r < 0.42 ? rand() * 52 : r < 0.84 ? w - 1 - rand() * 52 : 52 + rand() * (w - 104))
    trees.push({
      x,
      base: hill1(x) + 4 + Math.floor(rand() * 7),
      height: 9 + Math.floor(rand() * 8),
    })
  }
  trees.sort((a, b) => a.base - b.base)
  for (const t of trees) pine(ctx, t.x, t.base, t.height, P.pine)

  // Foreground meadow
  const hill2 = (x) => Math.round(90 + 2 * Math.sin(x * 0.08 + 2) + Math.sin(x * 0.21))
  for (let x = 0; x < w; x++) {
    const top = hill2(x)
    for (let y = top; y < h; y++) {
      const d = y - top
      let c = P.meadow.base
      if (d === 0) c = P.meadow.hi
      else if (d < 3) c = P.meadow.a
      else if ((x * 3 + y * 5) % 7 === 0) c = P.meadow.speck
      else if (d < 6 && (x + y) % 2 === 0) c = P.meadow.a
      px(ctx, x, y, c)
    }
  }

  // Flowers and grass tufts
  for (let i = 0; i < 46; i++) {
    const x = Math.floor(rand() * w)
    const y = hill2(x) + 3 + Math.floor(rand() * Math.max(1, h - hill2(x) - 4))
    px(ctx, x, y, P.petals[Math.floor(rand() * P.petals.length)])
    px(ctx, x, y + 1, P.tuft)
  }
  for (let i = 0; i < 24; i++) {
    const x = 1 + Math.floor(rand() * (w - 2))
    const y = hill2(x) + 4 + Math.floor(rand() * Math.max(1, h - hill2(x) - 5))
    px(ctx, x, y, P.tuft)
    px(ctx, x - 1, y - 1, P.tuft)
    px(ctx, x + 1, y - 1, P.tuft)
  }

  // Night: a few fireflies
  if (P.night) {
    const flyRand = rng(9)
    for (let i = 0; i < 9; i++) {
      const x = Math.floor(flyRand() * w)
      const y = 78 + Math.floor(flyRand() * 26)
      px(ctx, x, y, '#f3e2a0')
    }
  }
}

export function drawGlobe(ctx, w, h) {
  const cx = (w - 1) / 2
  const cy = (h - 1) / 2
  const r = w / 2 - 0.5
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const dx = x - cx
      const dy = y - cy
      const d = Math.hypot(dx, dy)
      if (d > r) continue
      if (d > r - 1.1) {
        px(ctx, x, y, '#1c4a32')
        continue
      }
      const light = (-dx * 0.65 - dy * 0.55) / r
      const n =
        Math.sin(x * 0.52 + 1.2) * Math.cos(y * 0.41 + 0.3) +
        0.7 * Math.sin((x * 0.9 + y * 0.7) * 0.33 + 2.0) +
        0.4 * Math.sin(y * 0.8)
      const cloudN = Math.sin(x * 0.31 + 4) * Math.sin(y * 0.57 + 1) + 0.5 * Math.cos((x - y) * 0.4)
      const dark = light < -0.35 || (light < -0.1 && (x + y) % 2 === 0)
      const bright = light > 0.45 && (x + y) % 2 === 0
      let c
      if (n > 0.55) c = dark ? '#4f9a5c' : bright ? '#c4e8a0' : '#8fcf7e'
      else c = dark ? '#2a7690' : bright ? '#8fd3dc' : '#3f9fb0'
      if (cloudN > 0.95) c = dark ? '#cfe0dc' : '#fbfaf2'
      px(ctx, x, y, c)
    }
  }
}

const spriteDrawer = (rows, palette) => (ctx) => {
  rows.forEach((row, y) => {
    ;[...row].forEach((ch, x) => {
      const c = palette[ch]
      if (c) px(ctx, x, y, c)
    })
  })
}

const GHOST = [
  '....oooooo....',
  '..oowwwwwwoo..',
  '.owwwwwwwwwwo.',
  '.owwwwwwwwwwo.',
  'owwwwwwwwwwwwo',
  'owweewwwweewwo',
  'owweewwwweewwo',
  'owwwwwwwwwwwwo',
  'owppwwwwwwppwo',
  'owwwwwoowwwwwo',
  'owwwwwwwwwwwwo',
  'owwwwwwwwwwwwo',
  'owwwwwwwwwwwwo',
  'owwwoowwoowwwo',
  '.ooo..oo..ooo.',
]
export const GHOST_SIZE = [GHOST[0].length, GHOST.length]
export const drawGhost = spriteDrawer(GHOST, {
  o: '#203a2f', w: '#fbfdf3', e: '#203a2f', p: '#e9a9b8',
})

const CURSOR = [
  'o...........',
  'oo..........',
  'owo.........',
  'owwo........',
  'owwwo.......',
  'owwwwo......',
  'owwwwwo.....',
  'owwwwwwo....',
  'owwwwwwwo...',
  'owwwwwwwwo..',
  'owwwwwwwwwo.',
  'owwwwwooooo.',
  'owwowwo.....',
  'owo.owwo....',
  'oo..owwo....',
  'o....owwo...',
  '.....owwo...',
  '......oo....',
]
export const CURSOR_SIZE = [CURSOR[0].length, CURSOR.length]
export const drawCursor = spriteDrawer(CURSOR, { o: '#1c4a32', w: '#fbfdf3' })

const WARNING = [
  '.....oo.....',
  '....oyyo....',
  '...oyyyyo...',
  '...oyooyo...',
  '..oyyooyyo..',
  '..oyyooyyo..',
  '.oyyyyyyyyo.',
  '.oyyyooyyyo.',
  'oyyyyyyyyyyo',
  'oooooooooooo',
]
export const WARNING_SIZE = [WARNING[0].length, WARNING.length]
export const drawWarning = spriteDrawer(WARNING, { o: '#203a2f', y: '#f2d06b' })
