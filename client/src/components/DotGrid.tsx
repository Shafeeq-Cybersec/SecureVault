import { useEffect, useRef } from 'react'

// Grid configuration
const SPACING = 30       // px between dot centers
const BASE_R = 1.5       // resting dot radius (px)
const PEAK_R = 4.0       // max radius at cursor center
const INFLUENCE = 140    // px radius of the glow falloff
const BG = '#0a1118'
// Resting dot color: subtle slate
const BASE_DOT = 'rgba(148,163,184,0.18)'

export function DotGrid() {
  const ref = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = ref.current!
    if (!canvas) return
    const ctx = canvas.getContext('2d')!
    if (!ctx) return

    let mx = -9999     // mouse x in CSS pixels
    let my = -9999     // mouse y in CSS pixels
    let rafId = 0
    let W = 0
    let H = 0

    // ---------- setup: size + DPI scale ----------
    function setup() {
      const dpr = window.devicePixelRatio || 1
      W = window.innerWidth
      H = window.innerHeight
      canvas.width = Math.round(W * dpr)
      canvas.height = Math.round(H * dpr)
      canvas.style.width = `${W}px`
      canvas.style.height = `${H}px`
      // Reset any previous transform before applying the new scale
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    }

    // ---------- main render loop ----------
    function draw() {
      // Background fill
      ctx.fillStyle = BG
      ctx.fillRect(0, 0, W, H)

      const cols = Math.floor(W / SPACING) + 2
      const rows = Math.floor(H / SPACING) + 2
      // Center the grid within the viewport
      const ox = (W % SPACING) / 2
      const oy = (H % SPACING) / 2

      const INF2 = INFLUENCE * INFLUENCE
      const glowing: { x: number; y: number; ease: number }[] = []

      // ---- Pass 1: batch all resting dots into a single path (fast) ----
      ctx.beginPath()
      for (let r = 0; r < rows; r++) {
        for (let c = 0; c < cols; c++) {
          const x = ox + c * SPACING
          const y = oy + r * SPACING
          const dx = x - mx
          const dy = y - my
          const d2 = dx * dx + dy * dy

          if (d2 >= INF2) {
            // Outside influence radius, use base dot
            ctx.moveTo(x + BASE_R, y)
            ctx.arc(x, y, BASE_R, 0, Math.PI * 2)
          } else {
            // Inside influence radius, compute precise distance
            const t = Math.max(0, 1 - Math.sqrt(d2) / INFLUENCE)
            const ease = t * t   // quadratic ease-in for sharper falloff
            if (ease < 0.006) {
              ctx.moveTo(x + BASE_R, y)
              ctx.arc(x, y, BASE_R, 0, Math.PI * 2)
            } else {
              glowing.push({ x, y, ease })
            }
          }
        }
      }
      ctx.fillStyle = BASE_DOT
      ctx.fill()

      // ---- Pass 2: glowing dots (halo + core) ----
      for (const { x, y, ease } of glowing) {
        // Outer glow halo via radial gradient
        const haloR = PEAK_R * 4 * ease
        const grad = ctx.createRadialGradient(x, y, 0, x, y, haloR)
        grad.addColorStop(0, `rgba(56,189,248,${(0.32 * ease).toFixed(3)})`)
        grad.addColorStop(1, 'rgba(56,189,248,0)')
        ctx.fillStyle = grad
        ctx.beginPath()
        ctx.arc(x, y, haloR, 0, Math.PI * 2)
        ctx.fill()

        // Core dot: interpolates size and alpha from base to peak
        const rDot = BASE_R + (PEAK_R - BASE_R) * ease
        const alpha = (0.2 + 0.8 * ease).toFixed(3)
        ctx.fillStyle = `rgba(56,189,248,${alpha})`
        ctx.beginPath()
        ctx.arc(x, y, rDot, 0, Math.PI * 2)
        ctx.fill()
      }

      rafId = requestAnimationFrame(draw)
    }

    // ---------- event handlers ----------
    const onMove = (e: MouseEvent) => { mx = e.clientX; my = e.clientY }
    const onLeave = () => { mx = -9999; my = -9999 }
    const onResize = () => {
      cancelAnimationFrame(rafId)
      setup()
      rafId = requestAnimationFrame(draw)
    }

    setup()
    rafId = requestAnimationFrame(draw)
    window.addEventListener('mousemove', onMove)
    document.addEventListener('mouseleave', onLeave)
    window.addEventListener('resize', onResize)

    return () => {
      cancelAnimationFrame(rafId)
      window.removeEventListener('mousemove', onMove)
      document.removeEventListener('mouseleave', onLeave)
      window.removeEventListener('resize', onResize)
    }
  }, [])

  return (
    <canvas
      ref={ref}
      aria-hidden="true"
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 0,
        pointerEvents: 'none',
        display: 'block',
      }}
    />
  )
}
