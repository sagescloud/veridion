const MAX_URL_LENGTH = 2048
const HAS_SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i
// Input without a scheme must start like a host (optionally with a port),
// which rejects things like "javascript:alert(1)" or "mailto:a@b.com".
const BARE_HOST_START = /^[^\s/?#:@]+(:\d+)?([/?#].*)?$/
const ALLOWED_PROTOCOLS = ['http:', 'https:']

function fail(error) {
  return { valid: false, error }
}

export function validateUrl(rawInput) {
  const input = typeof rawInput === 'string' ? rawInput.trim() : ''

  if (!input) {
    return fail('Enter a website address to scan.')
  }
  if (input.length > MAX_URL_LENGTH) {
    return fail(`That address is too long (limit ${MAX_URL_LENGTH} characters).`)
  }
  if (/\s/.test(input)) {
    return fail('Web addresses cannot contain spaces.')
  }

  const hasScheme = HAS_SCHEME.test(input)
  if (!hasScheme && !BARE_HOST_START.test(input)) {
    return fail("That doesn't look like a web address. Try something like example.com.")
  }

  const candidate = hasScheme ? input : `https://${input}`

  let parsed
  try {
    parsed = new URL(candidate)
  } catch {
    return fail("That doesn't look like a valid web address.")
  }

  if (!ALLOWED_PROTOCOLS.includes(parsed.protocol)) {
    return fail('Only http:// and https:// addresses can be scanned.')
  }

  const isIpv6 = parsed.hostname.startsWith('[')
  if (!parsed.hostname.includes('.') && !isIpv6) {
    return fail('Enter a full address, for example example.com.')
  }

  return { valid: true, url: candidate }
}