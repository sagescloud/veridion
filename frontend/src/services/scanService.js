import { env } from "../config/env";
import { startScan as startScanApi, getScan as getScanApi } from "./scanApi";
import { adaptScanResponse } from "./adapters/scanAdapter";
import {
  mockStartScan,
  mockGetScan,
} from "../mocks/mockScanApi";

export async function startScan(url, { signal } = {}) {
  const rawResponse = env.useMock
    ? await mockStartScan(url, { signal })
    : await startScanApi(url, { signal });

  return {
    ...adaptScanResponse(rawResponse),
    source: env.useMock ? "mock" : "api",
  };
}

export async function getScan(scanId, { signal } = {}) {
  const rawResponse = env.useMock
    ? await mockGetScan(scanId, { signal })
    : await getScanApi(scanId, { signal });

  return {
    ...adaptScanResponse(rawResponse),
    source: env.useMock ? "mock" : "api",
  };
}