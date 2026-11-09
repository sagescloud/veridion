export const moderateRiskScenario = {
  scan_id: "mock-moderate-risk",
  submitted_url: "https://suspicious-example.com",
  normalized_url: "https://suspicious-example.com",
  scanned_at: "2026-11-09T08:00:00.000Z",
  duration_ms: 4600,
  schema_version: "0.1",

  overall: {
    risk_score: 41,
    classification: "moderate",
    confidence: "medium",
    summary:
      "Several suspicious indicators were detected. Further verification is recommended.",
  },

  modules: [
    {
      module_id: "url_domain",
      name: "URL and Domain Analysis",
      status: "completed",
      summary: "The URL contains potentially suspicious characteristics.",
      risk_score: 55,
      findings: [
        {
          id: "mod-001",
          title: "Unusual subdomain structure",
          description: "The domain contains multiple nested subdomains.",
          severity: "medium",
          type: "suspicious_indicator",
          evidence: "Multiple subdomain levels were identified.",
          recommendation: "Verify the actual registered domain.",
        },
        {
          id: "mod-002",
          title: "Unusually long URL",
          description: "The submitted URL is longer than typical.",
          severity: "low",
          type: "suspicious_indicator",
          evidence: "The URL contains an unusually large number of characters.",
          recommendation: "Check whether the URL structure is expected.",
        },
      ],
    },
    {
      module_id: "threat_reputation",
      name: "Threat Reputation",
      status: "completed",
      summary: "No confirmed malicious listing was found.",
      risk_score: 0,
      findings: [],
    },
    {
      module_id: "certificate",
      name: "Certificate Analysis",
      status: "completed",
      summary: "Certificate is valid but was issued relatively recently.",
      risk_score: 35,
      findings: [
        {
          id: "mod-003",
          title: "Recently issued certificate",
          description: "The certificate has a relatively recent issuance date.",
          severity: "low",
          type: "informational",
          evidence: "Certificate issuance metadata indicates a recent date.",
          recommendation: "Consider this alongside other domain indicators.",
        },
      ],
    },
    {
      module_id: "security_config",
      name: "Website Security",
      status: "completed",
      summary: "Some recommended security headers are missing.",
      risk_score: 40,
      findings: [
        {
          id: "mod-004",
          title: "Missing security headers",
          description: "Recommended HSTS and CSP headers were not detected.",
          severity: "medium",
          type: "misconfiguration",
          evidence: "HSTS and Content-Security-Policy headers are absent.",
          recommendation: "Review the website's security header configuration.",
        },
      ],
    },
    {
      module_id: "website_behaviour",
      name: "Website Behaviour",
      status: "completed",
      summary: "A cross-domain redirect was observed.",
      risk_score: 45,
      findings: [
        {
          id: "mod-005",
          title: "Cross-domain redirect",
          description: "The website redirects to another domain.",
          severity: "medium",
          type: "suspicious_indicator",
          evidence: "A redirect to a different registered domain was observed.",
          recommendation: "Verify that the destination domain is legitimate.",
        },
      ],
    },
  ],

  findings: [],
  recommendations: [
    "Verify the registered domain and its ownership.",
    "Inspect the cross-domain redirect destination.",
    "Review missing security headers.",
    "Avoid entering sensitive information until the website is verified.",
  ],
};