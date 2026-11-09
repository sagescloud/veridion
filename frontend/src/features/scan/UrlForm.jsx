import { useId, useState } from 'react'
import Button from '../../components/ui/Button'
import { validateUrl } from '../../utils/validateUrl'

export default function UrlForm({ onSubmit, isLoading = false }) {
  const [value, setValue] = useState('')
  const [error, setError] = useState('')

  const inputId = useId()
  const hintId = `${inputId}-hint`
  const errorId = `${inputId}-error`

  const handleChange = (event) => {
    setValue(event.target.value)
    if (error) setError('')
  }

  const handleSubmit = (event) => {
    event.preventDefault()

    const result = validateUrl(value)
    if (!result.valid) {
      setError(result.error)
      return
    }

    setError('')
    onSubmit(result.url)
  }

  return (
    <form onSubmit={handleSubmit} noValidate>
      <label htmlFor={inputId} className="sr-only">
        Website address to scan
      </label>

      <div className="flex flex-col gap-3 sm:flex-row">
        <div className="relative flex-1">
          <span
            aria-hidden="true"
            className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 font-mono text-lg text-accent"
          >
            &gt;
          </span>
          <input
            id={inputId}
            type="text"
            inputMode="url"
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            placeholder="example.com/login"
            value={value}
            onChange={handleChange}
            aria-invalid={Boolean(error)}
            aria-describedby={error ? errorId : hintId}
            className="h-14 w-full border-2 border-line-strong bg-canvas pl-10 pr-4 font-mono text-base text-ink placeholder:text-ink-faint focus:border-accent focus:shadow-glow focus:outline-none aria-invalid:border-risk-critical"
          />
        </div>

        <Button type="submit" size="lg" disabled={isLoading}>
  {isLoading ? 'Scanning...' : 'Scan URL'}
</Button>
      </div>

      {error ? (
        <p id={errorId} role="alert" className="mt-3 font-mono text-sm text-risk-critical">
          {error}
        </p>
      ) : (
        <p id={hintId} className="mt-3 font-mono text-xs text-ink-faint">
          Submitted addresses are shown as plain text, never as clickable links.
        </p>
      )}
    </form>
  )
}