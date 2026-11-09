import { lowRiskScenario } from "./lowRisk";
import { moderateRiskScenario } from "./moderateRisk";
import { phishingScenario } from "./phishing";
import { incompleteScanScenario } from "./incompleteScan";
import { backendErrorScenario } from "./backendError";

export const mockScenarios = {
  lowRisk: lowRiskScenario,
  moderateRisk: moderateRiskScenario,
  phishing: phishingScenario,
  incomplete: incompleteScanScenario,
  backendError: backendErrorScenario,
};