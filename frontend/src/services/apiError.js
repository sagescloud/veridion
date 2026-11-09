export class ApiError extends Error {
  constructor({
    message = "Something went wrong.",
    code = "UNKNOWN_ERROR",
    status = null,
    details = null,
    requestId = null,
    retryable = false,
  } = {}) {
    super(message);

    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.details = details;
    this.requestId = requestId;
    this.retryable = retryable;
  }
}

export function normalizeApiError(error) {
  if (error instanceof ApiError) {
    return error;
  }

  if (error?.name === "AbortError") {
    return new ApiError({
      message: "The request was cancelled.",
      code: "REQUEST_CANCELLED",
    });
  }

  if (error?.name === "TimeoutError") {
    return new ApiError({
      message: "The request timed out. Please try again.",
      code: "REQUEST_TIMEOUT",
      retryable: true,
    });
  }

  return new ApiError({
    message: error?.message || "A network error occurred.",
    code: "NETWORK_ERROR",
    retryable: true,
  });
}