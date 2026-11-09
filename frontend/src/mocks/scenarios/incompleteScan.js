export const incompleteScanScenario = {
  scan_id: "mock-incomplete",
  submitted_url: "https://incomplete-example.com",
  normalized_url: "https://incomplete-example.com",
  scanned_at: "2026-11-09T08:00:00.000Z",
  duration_ms: 6800,
  schema_version: "0.1",

  overall: {
    risk_score: 57,
    classification: "high",
    confidence: "low",
    summary:
      "Some checks could not be completed. The available evidence indicates potential risk.",
  },

  modules: [
    {
      module_id: "url_domain",
      name: "URL and Domain Analysis",
      status: "completed",
      summary: "Some suspicious URL characteristics were identified.",
      risk_score: 55,
      findings: [
        {
          id: "inc-001",
          title: "Suspicious URL structure",
          description: "The URL contains unusual structural characteristics.",
          severity: "medium",
          type: "suspicious_indicator",
          evidence: "Sample URL structure analysis.",
          recommendation: "Verify the domain before interacting.",
        },
      ],
    },
    {
      module_id: "threat_reputation",
      name: "Threat Reputation",
      status: "unavailable",
      summary: "Threat reputation service could not be reached.",
      risk_score: null,
      findings: [],
      error: "Reputation provider unavailable.",
    },
    {
      module_id: "certificate",
      name: "Certificate Analysis",
      status: "failed",
      summary: "Certificate validation could not be completed.",
      risk_score: null,
      findings: [],
      error: "Certificate validation failed.",
    },
    {
      module_id: "security_config",
      name: "Website Security",
      status: "partial",
      summary: "Only some security configuration checks completed.",
      risk_score: 40,
      findings: [],
    },
    {
      module_id: "website_behaviour",
      name: "Website Behaviour",
      status: "completed",
      summary: "No significant behaviour indicators detected in available checks.",
      risk_score: 0,
      findings: [],
    },
  ],

  findings: [],
  recommendations: [
    "Treat this assessment with caution because some checks were unavailable.",
    "Retry the scan when the unavailable services are operational.",
    "Do not interpret missing security data as evidence that the website is safe.",
  ],
};