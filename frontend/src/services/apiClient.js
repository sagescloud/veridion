import { env } from "../config/env";
import { ApiError, normalizeApiError } from "./apiError";

export async function apiRequest(
  endpoint,
  {
    method = "GET",
    body,
    headers = {},
    signal: externalSignal,
    timeoutMs = env.requestTimeoutMs,
  } = {}
) {
  if (!env.apiBaseUrl) {
    throw new ApiError({
      message: "Backend API URL is not configured.",
      code: "API_URL_MISSING",
    });
  }

  const controller = new AbortController();
  let timedOut = false;

  const timeoutId = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  const handleExternalAbort = () => controller.abort();

  if (externalSignal?.aborted) {
    controller.abort();
  } else {
    externalSignal?.addEventListener("abort", handleExternalAbort, {
      once: true,
    });
  }

  try {
    const response = await fetch(
      `${env.apiBaseUrl}${endpoint}`,
      {
        method,
        headers: {
          Accept: "application/json",
          ...(body !== undefined
            ? { "Content-Type": "application/json" }
            : {}),
          ...headers,
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      }
    );

    const contentType = response.headers.get("content-type") || "";
    const isJson = contentType.includes("application/json");

    let data = null;

    if (isJson) {
      try {
        data = await response.json();
      } catch {
        throw new ApiError({
          message: "The backend returned invalid JSON.",
          code: "INVALID_RESPONSE",
          status: response.status,
        });
      }
    }

    if (!response.ok) {
      throw new ApiError({
        message:
          data?.error?.message ||
          data?.detail ||
          data?.message ||
          `Request failed with status ${response.status}.`,
        code: data?.error?.code || `HTTP_${response.status}`,
        status: response.status,
        details: data?.error?.details || null,
        requestId: data?.error?.request_id || null,
        retryable: response.status === 429 || response.status >= 500,
      });
    }

    return data;
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }

    if (timedOut) {
      throw new ApiError({
        message: "The request timed out. Please try again.",
        code: "REQUEST_TIMEOUT",
        retryable: true,
      });
    }

    throw normalizeApiError(error);
  } finally {
    clearTimeout(timeoutId);
    externalSignal?.removeEventListener("abort", handleExternalAbort);
  }
}