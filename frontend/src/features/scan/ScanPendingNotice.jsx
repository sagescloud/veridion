
export default function ScanPendingNotice({
  url,
  status,
  result,
  error,
}) {
  return (
    <div
      role={status === 'error' ? 'alert' : 'status'}
      aria-live={status === 'error' ? 'assertive' : 'polite'}
      className="mt-4 max-w-xl border border-line-strong bg-surface p-4"
    >
      <p className="font-mono text-xs tracking-widest text-accent">
        {status === 'scanning' && 'SCAN IN PROGRESS'}
        {status === 'success' && 'SCAN COMPLETE'}
        {status === 'error' && 'SCAN FAILED'}
      </p>

      <p className="mt-2 break-all font-mono text-sm text-ink">
        <span className="text-ink-faint">Submitted: </span>
        {url}
      </p>

      {status === 'scanning' && (
        <p className="mt-3 text-sm text-ink-muted">
          Analysing the submitted address. Please wait...
        </p>
      )}

      {status === 'error' && (
        <div className="mt-3 text-sm text-risk-critical">
          <p>{error?.message || 'An unexpected error occurred.'}</p>
          {error?.code && (
            <p className="mt-1 font-mono text-xs">
              Error code: {error.code}
            </p>
          )}
        </div>
      )}

      {status === 'success' && result && (
        <div className="mt-4 space-y-4">
          <div className="border-y border-line-strong py-3">
            <p className="font-mono text-xs text-ink-muted">
              OVERALL RISK SCORE
            </p>

            <p className="mt-1 font-display text-3xl text-accent">
              {result.riskScore ?? 'N/A'}
              <span className="text-base text-ink-muted">/100</span>
            </p>

            <p className="mt-1 font-mono text-sm text-ink">
              {result.classification?.toUpperCase()} RISK
              {' · '}
              {result.confidence?.toUpperCase()} CONFIDENCE
            </p>
          </div>

          {result.summary && (
            <div>
              <p className="font-mono text-xs tracking-widest text-accent">
                ANALYSIS SUMMARY
              </p>
              <p className="mt-2 text-sm text-ink-muted">
                {result.summary}
              </p>
            </div>
          )}

          <div>
            <p className="font-mono text-xs tracking-widest text-accent">
              FINDINGS ({result.findings.length})
            </p>

            {result.findings.length > 0 ? (
              <ul className="mt-2 space-y-3">
                {result.findings.map((finding, index) => (
                  <li
                    key={finding.id ?? index}
                    className="border-l-2 border-line-strong pl-3"
                  >
                    <p className="text-sm font-semibold text-ink">
                      {finding.title}
                    </p>
                    <p className="mt-1 text-xs text-ink-muted">
                      {finding.description}
                    </p>
                    {finding.recommendation && (
                      <p className="mt-1 text-xs text-accent">
                        Recommendation: {finding.recommendation}
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mt-2 text-sm text-ink-muted">
                No findings were returned by the available checks.
              </p>
            )}
          </div>

          <div>
            <p className="font-mono text-xs tracking-widest text-accent">
              ANALYSIS MODULES
            </p>
            <ul className="mt-2 space-y-1">
              {result.modules.map((module) => (
                <li
                  key={module.id}
                  className="flex justify-between gap-3 text-xs"
                >
                  <span className="text-ink-muted">{module.name}</span>
                  <span className="font-mono text-ink">
                    {module.status.toUpperCase()}
                  </span>
                </li>
              ))}
            </ul>
          </div>

          <p className="border-t border-line-strong pt-3 font-mono text-xs text-ink-faint">
            {result.source === 'mock'
              ? 'SIMULATED RESULT — NOT A LIVE SECURITY ASSESSMENT.'
              : 'Analysis result returned by the Veridion backend.'}
          </p>
        </div>
      )}
    </div>
  )
}
