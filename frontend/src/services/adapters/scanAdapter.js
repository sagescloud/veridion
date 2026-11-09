
import { ApiError } from "../apiError";
import {
  SCAN_CLASSIFICATION,
  CONFIDENCE_LEVEL,
} from "../../constants/scan";

const VALID_CLASSIFICATIONS = Object.values(SCAN_CLASSIFICATION);
const VALID_CONFIDENCE_LEVELS = Object.values(CONFIDENCE_LEVEL);

function normalizeEnum(value, allowedValues) {
  if (typeof value !== "string") {
    return "unknown";
  }

  const normalized = value.toLowerCase();

  return allowedValues.includes(normalized)
    ? normalized
    : "unknown";
}

function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

function adaptFinding(finding = {}) {
  return {
    id: finding.id ?? null,
    title: finding.title ?? "Untitled finding",
    description: finding.description ?? "",
    severity: finding.severity ?? "unknown",
    type: finding.type ?? "unknown",
    evidence: finding.evidence ?? null,
    recommendation: finding.recommendation ?? null,
  };
}

function adaptModule(module = {}) {
  return {
    id: module.module_id ?? "unknown",
    name: module.name ?? "Unknown module",
    status: module.status ?? "unknown",
    summary: module.summary ?? "",
    riskScore: module.risk_score ?? null,
    findings: normalizeArray(module.findings).map(adaptFinding),
    error: module.error ?? null,
  };
}

export function adaptScanResponse(raw) {
  if (!raw || typeof raw !== "object") {
    throw new ApiError({
      message: "The backend returned an invalid scan response.",
      code: "INVALID_SCAN_RESPONSE",
    });
  }

  if (!raw.scan_id || !raw.overall) {
    throw new ApiError({
      message: "The scan response is missing required information.",
      code: "INCOMPLETE_SCAN_RESPONSE",
    });
  }

  const overall = raw.overall;

  const modules = normalizeArray(raw.modules).map(adaptModule);

  const allFindings = normalizeArray(raw.findings).length
    ? normalizeArray(raw.findings)
    : modules.flatMap((module) => module.findings);

  const findings = allFindings
    .map(adaptFinding)
    .sort((a, b) => {
      const severityOrder = {
        critical: 0,
        high: 1,
        medium: 2,
        low: 3,
        info: 4,
        unknown: 5,
      };

      return (
        (severityOrder[a.severity] ?? 5) -
        (severityOrder[b.severity] ?? 5)
      );
    });

  return {
    id: raw.scan_id,
    submittedUrl: raw.submitted_url ?? "",
    normalizedUrl: raw.normalized_url ?? "",
    scannedAt: raw.scanned_at ?? null,
    durationMs: raw.duration_ms ?? null,

    riskScore: overall.risk_score ?? null,
    classification: normalizeEnum(
      overall.classification,
      VALID_CLASSIFICATIONS
    ),
    confidence: normalizeEnum(
      overall.confidence,
      VALID_CONFIDENCE_LEVELS
    ),
    summary: overall.summary ?? "",

    modules,
    findings,
    recommendations: normalizeArray(raw.recommendations),

    source: "api",
  };
}
