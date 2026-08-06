import { ensureRules, isDomesticDomain, updateRules } from "./rules";
import { isAdDomain } from "./adblock";
import { readConfig, type WorkerConfig } from "./config";