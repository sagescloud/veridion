export default function ScanPendingNotice({ url }) {
  return (
    <div
      role="status"
      className="mt-4 max-w-xl border border-line-strong bg-surface p-4"
    >
      <p className="font-mono text-xs tracking-widest text-accent">PREVIEW BUILD</p>
      <p className="mt-2 text-sm text-ink-muted">
        This address passed basic validation. Scanning is not connected yet, so
        no analysis was performed.
      </p>
      <p className="mt-2 break-all font-mono text-sm text-ink">
        <span className="text-ink-faint">Submitted: </span>
        {url}
      </p>
    </div>
  )
}