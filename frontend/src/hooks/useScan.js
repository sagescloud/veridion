import { useCallback, useEffect, useRef, useState } from "react";
import { SCAN_STATE } from "../constants/scan";
import { startScan as startScanService } from "../services/scanService";
import { normalizeApiError } from "../services/apiError";

export function useScan() {
  const [status, setStatus] = useState(SCAN_STATE.IDLE);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const controllerRef = useRef(null);

  const startScan = useCallback(async (url) => {
    controllerRef.current?.abort();

    const controller = new AbortController();
    controllerRef.current = controller;

    setStatus(SCAN_STATE.SCANNING);
    setResult(null);
    setError(null);

    try {
      const scanResult = await startScanService(url, {
        signal: controller.signal,
      });

      if (controller.signal.aborted) return null;

      setResult(scanResult);
      setStatus(SCAN_STATE.SUCCESS);

      return scanResult;
    } catch (err) {
      if (controller.signal.aborted) return null;

      const normalizedError = normalizeApiError(err);

      setError(normalizedError);
      setStatus(SCAN_STATE.ERROR);

      return null;
    } finally {
      if (controllerRef.current === controller) {
        controllerRef.current = null;
      }
    }
  }, []);

  const cancelScan = useCallback(() => {
    controllerRef.current?.abort();
    controllerRef.current = null;

    setStatus(SCAN_STATE.IDLE);
    setError(null);
  }, []);

  const resetScan = useCallback(() => {
    controllerRef.current?.abort();
    controllerRef.current = null;

    setStatus(SCAN_STATE.IDLE);
    setResult(null);
    setError(null);
  }, []);

  useEffect(() => {
    return () => {
      controllerRef.current?.abort();
    };
  }, []);

  return {
    status,
    result,
    error,
    startScan,
    cancelScan,
    resetScan,
    isScanning: status === SCAN_STATE.SCANNING,
  };
}