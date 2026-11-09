export const heroChips = [
  'URL & domain',
  'Threat reputation',
  'SSL/TLS',
  'Security config',
  'Redirect behaviour',
]

// Illustrative sample only. Not a real scan result.
export const terminalSample = {
  command: 'veridion scan paypa1-login.example',
  findings: [
    {
      id: 't1',
      tone: 'high',
      tag: 'HIGH',
      label: 'url_domain',
      text: 'Resembles paypal.com (similarity 0.93)',
    },
    {
      id: 't2',
      tone: 'moderate',
      tag: 'MED',
      label: 'security_config',
      text: 'HTTPS not available',
    },
    {
      id: 't3',
      tone: 'moderate',
      tag: 'MED',
      label: 'behaviour',
      text: '2 redirects to another domain',
    },
    {
      id: 't4',
      tone: 'muted',
      tag: 'N/A',
      label: 'reputation',
      text: 'Provider unavailable (not a clean result)',
    },
    {
      id: 't5',
      tone: 'muted',
      tag: 'N/A',
      label: 'certificate',
      text: 'Skipped: site does not use HTTPS',
    },
  ],
  summary: { score: 68, classification: 'HIGH', confidence: 'MEDIUM' },
  note: 'Unavailable checks are never counted as clean.',
}

export const howItWorksSteps = [
  {
    id: 'submit',
    number: '01',
    title: 'Submit a link',
    description:
      'Paste any website address. Veridion validates it before anything else happens.',
  },
  {
    id: 'analyse',
    number: '02',
    title: 'Run layered checks',
    description:
      'URL and domain, threat reputation, SSL/TLS, security configuration and redirect behaviour are examined independently.',
  },
  {
    id: 'combine',
    number: '03',
    title: 'Weigh the evidence',
    description:
      'Findings are combined into a risk score and a separate confidence rating, so missing data is never mistaken for safety.',
  },
  {
    id: 'act',
    number: '04',
    title: 'Know what to do next',
    description:
      'Every finding explains what was detected, why it matters, and what you should do about it.',
  },
]

export const capabilities = [
  {
    id: 'url-domain',
    number: '01',
    tag: 'URL / DOMAIN',
    title: 'URL & Domain Intelligence',
    description:
      'Spots lookalike domains, typosquatting, IP-based links, misleading subdomains and homograph tricks.',
  },
  {
    id: 'reputation',
    number: '02',
    tag: 'REPUTATION',
    title: 'Threat Reputation',
    description:
      'Checks the URL against threat intelligence sources. A lack of reports never means a site is safe.',
  },
  {
    id: 'certificate',
    number: '03',
    tag: 'SSL / TLS',
    title: 'Certificate Validation',
    description:
      'Inspects validity, expiry, issuer and hostname match. A valid certificate alone does not prove a site is legitimate.',
  },
  {
    id: 'security-config',
    number: '04',
    tag: 'CONFIG',
    title: 'Security Configuration',
    description:
      'Reviews HTTPS availability and recommended security headers, and separates weak setup from malicious activity.',
  },
  {
    id: 'behaviour',
    number: '05',
    tag: 'BEHAVIOUR',
    title: 'Redirect Behaviour',
    description:
      'Follows redirect chains to expose suspicious hops and unexpected destinations.',
  },
  {
    id: 'explainable',
    number: '06',
    tag: 'EXPLAINABLE',
    title: 'Explainable Assessment',
    description:
      'A risk score, a confidence rating and supporting evidence for every classification, written for non-experts.',
  },
]