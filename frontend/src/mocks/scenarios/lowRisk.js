export const lowRiskScenario = {
  scan_id: "mock-low-risk",
  submitted_url: "https://example.com",
  normalized_url: "https://example.com",
  scanned_at: "2026-11-09T08:00:00.000Z",
  duration_ms: 3200,
  schema_version: "0.1",

  overall: {
    risk_score: 8,
    classification: "low",
    confidence: "high",
    summary:
      "No significant threats were detected in the available security checks.",
  },

  modules: [
    {
      module_id: "url_domain",
      name: "URL and Domain Analysis",
      status: "completed",
      summary: "No significant URL or domain indicators detected.",
      risk_score: 5,
      findings: [],
    },
    {
      module_id: "threat_reputation",
      name: "Threat Reputation",
      status: "completed",
      summary: "No known threat reports found in available sources.",
      risk_score: 0,
      findings: [],
    },
    {
      module_id: "certificate",
      name: "Certificate Analysis",
      status: "completed",
      summary: "The HTTPS certificate is valid.",
      risk_score: 0,
      findings: [],
    },
    {
      module_id: "security_config",
      name: "Website Security",
      status: "completed",
      summary: "Minor security configuration improvements recommended.",
      risk_score: 15,
      findings: [
        {
          id: "low-001",
          title: "Missing security header",
          description: "One recommended security header was not detected.",
          severity: "low",
          type: "misconfiguration",
          evidence: "A recommended HTTP security header is absent.",
          recommendation: "Review and configure appropriate security headers.",
        },
      ],
    },
    {
      module_id: "website_behaviour",
      name: "Website Behaviour",
      status: "completed",
      summary: "No suspicious redirect behaviour detected.",
      risk_score: 0,
      findings: [],
    },
  ],

  findings: [
    {
      id: "low-001",
      title: "Missing security header",
      description: "One recommended security header was not detected.",
      severity: "low",
      type: "misconfiguration",
      evidence: "A recommended HTTP security header is absent.",
      recommendation: "Review and configure appropriate security headers.",
    },
  ],

  recommendations: [
    "Review the website's HTTP security headers.",
    "Remember that a valid HTTPS certificate alone does not establish legitimacy.",
  ],
};