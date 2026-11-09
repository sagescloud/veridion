const readBoolean = (value, fallback = false) => {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }

  return value === "true";
};

const readNumber = (value, fallback) => {
  const parsed = Number(value);

  return Number.isFinite(parsed) && parsed > 0
    ? parsed
    : fallback;
};

const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL || "")
  .trim()
  .replace(/\/+$/, "");

export const env = {
  useMock: readBoolean(import.meta.env.VITE_USE_MOCK, true),
  apiBaseUrl,
  requestTimeoutMs: readNumber(
    import.meta.env.VITE_REQUEST_TIMEOUT_MS,
    45000
  ),
};