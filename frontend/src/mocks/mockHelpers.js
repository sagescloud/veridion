export function createMockScanId() {
  return `mock-${crypto.randomUUID()}`;
}

export function getCurrentTimestamp() {
  return new Date().toISOString();
}

export function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException("Request cancelled", "AbortError"));
      return;
    }

    const timeoutId = setTimeout(() => {
      cleanup();
      resolve();
    }, ms);

    function handleAbort() {
      clearTimeout(timeoutId);
      cleanup();
      reject(new DOMException("Request cancelled", "AbortError"));
    }

    function cleanup() {
      signal?.removeEventListener("abort", handleAbort);
    }

    signal?.addEventListener("abort", handleAbort, { once: true });
  });
}