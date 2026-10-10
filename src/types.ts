export interface Env {
  RULES_KV: KVNamespace;
  DOH_PATH?: string;
  DOMESTIC_DOH_URL?: string;
  DOMESTIC_FALLBACK_DOH_URL?: string;
  GLOBAL_DOH_URL?: string;
  GLOBAL_FALLBACK_DOH_URL?: string;
  ADBLOCK_ENABLED?: string;
  ADBLOCK_LIST_URL?: string;
  ADBLOCK_EXTRA_BLOCKLIST?: string;
  ADBLOCK_ALLOWLIST?: string;
  ADBLOCK_RESPONSE?: string;
  STATS_TOKEN?: string;
}

export interface RuleManifest {
  active: string;
  previous: string | null;
  sha256: string;
  size: number;
  updatedAt: string;
}

// 只依赖 waitUntil，测试可直接传最小实现。
export interface WaitUntil {
  waitUntil(promise: Promise<unknown>): void;
}
