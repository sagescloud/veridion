import { ApiError } from "../apiError";

import {
  SCAN_STATUS,
  MODULE_STATUS,
  SCAN_CLASSIFICATION,
  CONFIDENCE_LEVEL,
  SEVERITY,
  SEVERITY_RANK,
  FINDING_TYPE,
  PRIORITY,
  MODULE_LABELS,
} from "../../constants/scan";

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  );
}

function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

function normalizeString(value, fallback = "") {
  return typeof value === "string" ? value : fallback;
}

function normalizeNumber(value) {
  return typeof value === "number" && Number.isFinite(value)
    ? value
    : null;
}

function normalizeEnum(value, allowedValues) {
  if (typeof value !== "string") {
    return "unknown";
  }

  const normalized = value.toLowerCase();

  return allowedValues.includes(normalized)
    ? normalized
    : "unknown";
}

function normalizeEvidence(evidence) {
  // Older mock format uses a plain string.
  if (typeof evidence === "string") {
    return evidence;
  }

  // Actual API format uses an array of { label, value } objects.
  return normalizeArray(evidence)
    .filter(isPlainObject)
    .map((item) => ({
      label: normalizeString(item.label),
      value: normalizeString(item.value),
    }));
}

function adaptFinding(finding = {}) {
  return {
    id: normalizeString(finding.id, null),
    code: normalizeString(finding.code, null),
    title: normalizeString(finding.title, "Untitled finding"),
    description: normalizeString(finding.description),
    severity: normalizeEnum(
      finding.severity,
      Object.values(SEVERITY)
    ),
    type: normalizeEnum(
      finding.type,
      Object.values(FINDING_TYPE)
    ),
    evidence: normalizeEvidence(finding.evidence),
    recommendation: normalizeString(
      finding.recommendation,
      ""
    ),
  };
}

function adaptModule(module = {}) {
  const id = normalizeString(
    module.id || module.module_id,
    "unknown"
  );

  const findings = normalizeArray(module.findings)
    .map(adaptFinding);

  return {
    id,
    name: normalizeString(
      module.name,
      MODULE_LABELS[id] || "Unknown module"
    ),
    status: normalizeEnum(
      module.status,
      Object.values(MODULE_STATUS)
    ),
    summary: normalizeString(
      module.summary || module.status_reason?.message
    ),
    riskScore: normalizeNumber(module.risk_score),
    findings,
    error: normalizeString(module.error, null),
    statusReason: isPlainObject(module.status_reason)
      ? {
          code: normalizeString(module.status_reason.code),
          message: normalizeString(module.status_reason.message),
        }
      : null,
    details: isPlainObject(module.details)
      ? module.details
      : null,
  };
}

function adaptRecommendation(recommendation, index) {
  // Older mocks use plain strings.
  if (typeof recommendation === "string") {
    return {
      id: `mock-recommendation-${index}`,
      priority: PRIORITY.MEDIUM,
      text: recommendation,
      relatedFindingIds: [],
    };
  }

  if (!isPlainObject(recommendation)) {
    return null;
  }

  return {
    id: normalizeString(recommendation.id, `recommendation-${index}`),
    priority: normalizeEnum(
      recommendation.priority,
      Object.values(PRIORITY)
    ),
    text: normalizeString(recommendation.text),
    relatedFindingIds: normalizeArray(
      recommendation.related_finding_ids
    ),
  };
}

function adaptOverall(overall = {}) {
  const confidenceValue = isPlainObject(overall.confidence)
    ? overall.confidence.level
    : overall.confidence;

  const confidenceReasons = isPlainObject(overall.confidence)
    ? normalizeArray(overall.confidence.reasons)
    : [];

  return {
    riskScore: normalizeNumber(overall.risk_score),

    classification: normalizeEnum(
      overall.classification,
      Object.values(SCAN_CLASSIFICATION)
    ),

    confidence: normalizeEnum(
      confidenceValue,
      Object.values(CONFIDENCE_LEVEL)
    ),

    confidenceReasons,

    summary: normalizeString(overall.summary),

    escalation: isPlainObject(overall.escalation)
      ? {
          code: normalizeString(overall.escalation.code),
          message: normalizeString(overall.escalation.message),
        }
      : null,
  };
}

function createSummary(overall, modules, findings) {
  if (overall.summary) {
    return overall.summary;
  }

  if (overall.classification === "inconclusive") {
    return "The assessment was inconclusive because insufficient security evidence was available.";
  }

  const completed = modules.filter(
    (module) => module.status === "completed"
  ).length;

  const partial = modules.filter(
    (module) => module.status === "partial"
  ).length;

  const unavailable = modules.length - completed - partial;

  const coverage = `${completed} of ${modules.length} modules completed`;

  let summary = `The website was classified as ${overall.classification} risk with ${overall.confidence} confidence. ${coverage}.`;

  if (partial > 0 || unavailable > 0) {
    summary += " Some checks were incomplete or unavailable.";
  }

  if (findings.length > 0) {
    summary += ` ${findings.length} finding(s) were identified.`;
  }

  return summary;
}

function calculateCoverage(modules) {
  const completed = modules.filter(
    (module) => module.status === "completed"
  ).length;

  const partial = modules.filter(
    (module) => module.status === "partial"
  ).length;

  const notRun = modules.length - completed - partial;

  return {
    total: modules.length,
    completed,
    partial,
    notRun,
  };
}

export function adaptScanResponse(raw) {
  if (!isPlainObject(raw)) {
    throw new ApiError({
      message: "The backend returned an invalid scan response.",
      code: "INVALID_SCAN_RESPONSE",
    });
  }

  if (
    !raw.scan_id ||
    !isPlainObject(raw.overall)
  ) {
    throw new ApiError({
      message: "The scan response is missing required information.",
      code: "INCOMPLETE_SCAN_RESPONSE",
    });
  }

  const overall = adaptOverall(raw.overall);

  const modules = normalizeArray(raw.modules)
    .map(adaptModule);

  // API findings are nested inside modules.
  // Older mocks may also contain a top-level findings array.
  const moduleFindings = modules.flatMap(
    (module) => module.findings
  );

  const topLevelFindings = normalizeArray(raw.findings)
    .map(adaptFinding);

  const findings = (
    topLevelFindings.length > 0
      ? topLevelFindings
      : moduleFindings
  ).sort((a, b) => {
    return (
      (SEVERITY_RANK[b.severity] ?? 0) -
      (SEVERITY_RANK[a.severity] ?? 0)
    );
  });

  const recommendations = normalizeArray(raw.recommendations)
    .map(adaptRecommendation)
    .filter(Boolean);

  // Connect backend recommendations to their related findings.
  for (const finding of findings) {
    if (finding.recommendation) continue;

    const relatedRecommendation = recommendations.find(
      (recommendation) =>
        recommendation.relatedFindingIds.includes(finding.id)
    );

    if (relatedRecommendation) {
      finding.recommendation = relatedRecommendation.text;
    }
  }

  overall.summary = createSummary(
    overall,
    modules,
    findings
  );

  return {
    id: normalizeString(raw.scan_id),
    schemaVersion: normalizeString(raw.schema_version, null),

    status: normalizeEnum(
      raw.status,
      Object.values(SCAN_STATUS)
    ),

    submittedUrl: normalizeString(raw.submitted_url),
    normalizedUrl: normalizeString(raw.normalized_url),
    scannedAt: normalizeString(raw.scanned_at, null),
    durationMs: normalizeNumber(raw.duration_ms),

    riskScore: overall.riskScore,
    classification: overall.classification,
    confidence: overall.confidence,
    confidenceReasons: overall.confidenceReasons,
    summary: overall.summary,
    escalation: overall.escalation,

    modules,
    findings,
    recommendations,

    coverage: calculateCoverage(modules),

    community: isPlainObject(raw.community)
      ? raw.community
      : null,

    source: "api",
  };
}