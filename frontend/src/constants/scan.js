export const SCAN_STATE = {
  IDLE: "idle",
  SCANNING: "scanning",
  SUCCESS: "success",
  ERROR: "error",
};

export const SCAN_STATUS = {
  PENDING: "pending",
  RUNNING: "running",
  COMPLETED: "completed",
  UNKNOWN: "unknown",
};

export const MODULE_STATUS = {
  COMPLETED: "completed",
  PARTIAL: "partial",
  UNAVAILABLE: "unavailable",
  FAILED: "failed",
  SKIPPED: "skipped",
  UNKNOWN: "unknown",
};

export const SCAN_CLASSIFICATION = {
  LOW: "low",
  MODERATE: "moderate",
  HIGH: "high",
  CRITICAL: "critical",
  INCONCLUSIVE: "inconclusive",
  UNKNOWN: "unknown",
};

export const CONFIDENCE_LEVEL = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  UNKNOWN: "unknown",
};

export const SEVERITY = {
  INFO: "info",
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
  UNKNOWN: "unknown",
};

export const SEVERITY_RANK = {
  unknown: 0,
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
};

export const FINDING_TYPE = {
  MALICIOUS_INDICATOR: "malicious_indicator",
  SUSPICIOUS_INDICATOR: "suspicious_indicator",
  MISCONFIGURATION: "misconfiguration",
  INFORMATIONAL: "informational",
  UNKNOWN: "unknown",
};

export const PRIORITY = {
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
};

export const MODULE_LABELS = {
  url_domain: "URL and Domain Analysis",
  threat_reputation: "Threat Reputation",
  certificate: "Certificate Analysis",
  security_config: "Website Security",
  website_behaviour: "Website Behaviour",
};

export const RISK_LEVEL_LABELS = {
  low: "Low Risk",
  moderate: "Moderate Risk",
  high: "High Risk",
  critical: "Critical Risk",
  inconclusive: "Inconclusive",
  unknown: "Unknown Risk",
};

export const CONFIDENCE_LABELS = {
  low: "Low Confidence",
  medium: "Medium Confidence",
  high: "High Confidence",
  unknown: "Confidence Unavailable",
};