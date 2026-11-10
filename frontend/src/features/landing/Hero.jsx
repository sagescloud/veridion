import Container from '../../components/layout/Container'
import RetroWindow from '../../components/ui/RetroWindow'
import {
  PixelScene, PixelGlobe, PixelGhost, PixelCursor, PixelWarning,
} from '../../components/pixel/PixelCanvas'
import UrlForm from '../scan/UrlForm'
import ScanPendingNotice from '../scan/ScanPendingNotice'
import HeroTerminal from './HeroTerminal'
import { heroChips } from '../../data/landingContent'
import { SCAN_STATE } from '../../constants/scan'

function Taskbar({ label }) {
  return (
    <div className="taskbar">
      <div className="flex items-center gap-2">
        <a href="#scanner" className="win-btn !py-0.5">
          <svg width="14" height="14" viewBox="0 0 14 14" shapeRendering="crispEdges" aria-hidden="true">
            <rect x="0" y="0" width="6" height="6" fill="#e9a9b8" />
            <rect x="8" y="0" width="6" height="6" fill="#2f7d4f" />
            <rect x="0" y="8" width="6" height="6" fill="#a9d49a" />
            <rect x="8" y="8" width="6" height="6" fill="#f2d06b" />
          </svg>
          Start
        </a>
        <span aria-hidden="true" className="taskbar-item hidden sm:inline-flex">
          veridion_scanner.exe
        </span>
      </div>
      <span aria-hidden="true" className="taskbar-item">{label}</span>
    </div>
  )
}

export default function Hero({ onScan, submittedUrl, status, result, error }) {
  const scanning = status === SCAN_STATE.SCANNING
  const tone = scanning
    ? 'busy'
    : status === SCAN_STATE.SUCCESS
      ? 'done'
      : status === SCAN_STATE.ERROR
        ? 'fail'
        : 'idle'
  const label = { busy: 'Scanning…', done: 'Scan complete', fail: 'Scan failed', idle: 'Ready' }[tone]

  return (
    <section id="scan" className="relative isolate scroll-mt-14 overflow-hidden pb-24 pt-8 sm:pt-12 lg:pb-28">
      <PixelScene className="pixel-scene absolute inset-0 -z-10 h-full w-full" />

      <Container className="relative">
        {/* Title lockup: one-line pixel wordmark over the globe */}
        <div className="relative min-h-[11rem] sm:min-h-[14rem] lg:min-h-[19rem]">
          <PixelGlobe className="float-slow absolute right-0 top-0 w-36 sm:w-56 lg:right-[4%] lg:w-[24rem]" />
          <PixelCursor className="absolute left-[52%] top-[62%] hidden w-6 sm:block lg:w-10" />
          <PixelCursor className="absolute right-[2%] top-[78%] hidden w-5 scale-x-[-1] lg:block" />

          <div className="relative">
            <h1
              aria-label="Veridion, digital trust intelligence"
              className="pixel-title whitespace-nowrap text-[clamp(2.75rem,12vw,9.5rem)] uppercase leading-[0.95]"
            >
              <span aria-hidden="true">Veridion</span>
            </h1>
            <p className="mt-4 inline-block border-2 border-navy bg-cobalt px-3 py-1.5 font-pixel text-base font-semibold tracking-wide text-surface sm:text-lg">
              Digital trust intelligence
            </p>
          </div>
        </div>

        {/* Overlapping windows: the scanner is the hero element */}
        <div className="relative z-10 -mt-2 grid gap-8 lg:-mt-12 lg:grid-cols-12 lg:gap-6">
          <RetroWindow
            id="scanner"
            titleId="scanner-title"
            aria-labelledby="scanner-title"
            title="veridion_scanner.exe"
            className="scroll-mt-20 lg:col-span-8"
            bodyClassName="p-6 sm:p-10 lg:min-h-[27rem]"
          >
            <p className="font-pixel text-3xl font-bold leading-tight text-ink sm:text-4xl lg:text-5xl">
              Trust <span className="text-cobalt">evidence</span>, not appearance.
            </p>
            <p className="mt-4 max-w-2xl text-lg text-ink-muted">
              Paste a link and Veridion examines the URL, domain, certificate,
              reputation and behaviour of the site, then explains what it found,
              why it matters and what to do next.
            </p>

            <div aria-hidden="true" className="mt-6 flex items-center gap-3">
              <div className="pixel-loader" data-tone={tone}>
                <div className="pixel-loader-fill" />
              </div>
              <span className="w-32 shrink-0 font-pixel text-base font-semibold text-ink">
                {label}
              </span>
            </div>

            <div className="mt-5 [&_button]:min-h-14 [&_input]:min-h-14 [&_input]:text-base">
              <UrlForm onSubmit={onScan} isLoading={scanning} />
            </div>

            {submittedUrl && (
              <ScanPendingNotice url={submittedUrl} status={status} result={result} error={error} />
            )}
          </RetroWindow>

          <div className="relative lg:col-span-4 lg:pt-20">
            <PixelGhost className="float-slow absolute -top-10 right-6 z-20 w-14 sm:w-[4.5rem] lg:top-6" />
            <HeroTerminal />

            <RetroWindow
              title="warning.exe"
              className="relative z-10 -mt-3 ml-6 max-w-sm lg:-ml-8 lg:-mt-6"
              bodyClassName="flex items-start gap-3 p-4"
            >
              <PixelWarning className="mt-1 w-10 shrink-0" />
              <div>
                <p className="font-pixel text-base font-semibold leading-snug text-ink">
                  Looks legit? Looks can lie.
                </p>
                <p className="mt-1 text-sm text-ink-muted">Scan the link before you click it.</p>
                <a href="#scanner" className="win-btn mt-3">Scan first</a>
              </div>
            </RetroWindow>
          </div>
        </div>

        <ul aria-label="Analysis layers" className="relative z-10 mt-10 flex flex-wrap gap-2">
          {heroChips.map((chip) => (
            <li
              key={chip}
              className="border-2 border-navy bg-surface px-3 py-1 font-pixel text-sm font-medium text-ink"
            >
              {chip}
            </li>
          ))}
        </ul>
      </Container>

      <Taskbar label={label} />
    </section>
  )
}
