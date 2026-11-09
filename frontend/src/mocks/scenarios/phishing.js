export const phishingScenario = {
  scan_id: "mock-phishing",
  submitted_url: "https://paypaI-example.com",
  normalized_url: "https://paypaI-example.com",
  scanned_at: "2026-11-09T08:00:00.000Z",
  duration_ms: 5100,
  schema_version: "0.1",

  overall: {
    risk_score: 94,
    classification: "critical",
    confidence: "high",
    summary:
      "Multiple strong indicators of phishing activity were detected.",
    escalation: "CONFIRMED_PHISHING",
  },

  modules: [
    {
      module_id: "url_domain",
      name: "URL and Domain Analysis",
      status: "completed",
      summary: "Strong brand impersonation indicators detected.",
      risk_score: 95,
      findings: [
        {
          id: "phish-001",
          title: "Brand impersonation detected",
          description:
            "The submitted domain closely resembles a well-known financial brand.",
          severity: "critical",
          type: "malicious_indicator",
          evidence: "High similarity between the submitted domain and the brand name.",
          recommendation: "Do not enter credentials or personal information.",
        },
      ],
    },
    {
      module_id: "threat_reputation",
      name: "Threat Reputation",
      status: "completed",
      summary: "Threat intelligence indicates known phishing activity.",
      risk_score: 100,
      findings: [
        {
          id: "phish-002",
          title: "Known phishing indicator",
          description: "The domain appears in a simulated threat intelligence result.",
          severity: "critical",
          type: "malicious_indicator",
          evidence: "Sample threat intelligence match.",
          recommendation: "Avoid visiting or interacting with this website.",
        },
      ],
    },
    {
      module_id: "certificate",
      name: "Certificate Analysis",
      status: "completed",
      summary: "A certificate hostname mismatch was detected.",
      risk_score: 90,
      findings: [
        {
          id: "phish-003",
          title: "Certificate hostname mismatch",
          description: "The certificate does not match the requested hostname.",
          severity: "high",
          type: "suspicious_indicator",
          evidence: "Sample certificate hostname validation failure.",
          recommendation: "Do not trust the connection until independently verified.",
        },
      ],
    },
    {
      module_id: "security_config",
      name: "Website Security",
      status: "completed",
      summary: "Several security configuration concerns were identified.",
      risk_score: 70,
      findings: [],
    },
    {
      module_id: "website_behaviour",
      name: "Website Behaviour",
      status: "completed",
      summary: "Suspicious cross-domain redirects were observed.",
      risk_score: 90,
      findings: [
        {
          id: "phish-004",
          title: "Suspicious redirect behaviour",
          description: "The website redirects across domains unexpectedly.",
          severity: "high",
          type: "suspicious_indicator",
          evidence: "Sample cross-domain redirect chain.",
          recommendation: "Avoid following unexpected redirects.",
        },
      ],
    },
  ],

  findings: [],
  recommendations: [
    "Do not enter passwords, banking details or personal information.",
    "Do not download files from this website.",
    "Navigate to the legitimate service using its independently verified address.",
    "Report the suspicious URL to the platform's threat intelligence system.",
  ],
};