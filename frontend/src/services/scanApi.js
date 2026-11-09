import { apiRequest } from "./apiClient";

export function startScan(url, { signal } = {}) {
  return apiRequest("/api/scan", {
    method: "POST",
    body: { url },
    signal,
  });
}

export function getScan(scanId, { signal } = {}) {
  if (!scanId) {
    throw new Error("A scan ID is required.");
  }

  return apiRequest(
    `/api/scan/${encodeURIComponent(scanId)}`,
    { signal }
  );
}