import { ApiError } from "../services/apiError";
import { mockScenarios } from "./scenarios";
import {
  createMockScanId,
  getCurrentTimestamp,
  sleep,
} from "./mockHelpers";

const scanStore = new Map();

function selectScenario(url) {
  const hostname = new URL(url).hostname.toLowerCase();

  if (hostname.includes("fail") || hostname.includes("error")) {
    return "backendError";
  }

  if (hostname.includes("phish")) {
    return "phishing";
  }

  if (hostname.includes("suspicious")) {
    return "moderateRisk";
  }

  if (hostname.includes("incomplete")) {
    return "incomplete";
  }

  return "lowRisk";
}

export async function mockStartScan(url, { signal } = {}) {
  await sleep(1800, signal);

  const scenarioName = selectScenario(url);

  if (scenarioName === "backendError") {
    throw new ApiError({
      message: mockScenarios.backendError.error.message,
      code: mockScenarios.backendError.error.code,
      status: 500,
      retryable: true,
    });
  }

  const scenario = structuredClone(mockScenarios[scenarioName]);

  const scan = {
    ...scenario,
    scan_id: createMockScanId(),
    submitted_url: url,
    normalized_url: url,
    scanned_at: getCurrentTimestamp(),
  };

  scanStore.set(scan.scan_id, scan);

  return structuredClone(scan);
}

export async function mockGetScan(scanId, { signal } = {}) {
  await sleep(700, signal);

  const scan = scanStore.get(scanId);

  if (!scan) {
    throw new ApiError({
      message: "The requested mock scan could not be found.",
      code: "SCAN_NOT_FOUND",
      status: 404,
    });
  }

  return structuredClone(scan);
}