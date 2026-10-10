// 广告/追踪域名拦截列表：复用国内域名规则的 KV + manifest 机制。
// 数据形态为按字节序严格递增的 LF 分隔域名列表，查询用二分查找，
// 避免"生成端哈希与运行端不一致"这类布隆过滤器故障模式，且支持白名单豁免。
import { toArrayBuffer } from "./binary";
import { binarySearchRegion, sha256Hex } from "./rules";
import type { Env, RuleManifest } from "./types";

export const DEFAULT_ADBLOCK_LIST_URL = "https://anti-ad.net/domains.txt";
export const ADLIST_MANIFEST_KEY = "adlist:active";
export const ADLIST_ALLOWLIST_KEY = "adlist:allowlist";
export const MAX_AD_BYTES = 8 * 1024 * 1024;
const MIN_AD_BYTES = 1;
const AD_RECHECK_MS = 15 * 60 * 1000;
const BOOTSTRAP_RETRY_MS = 60 * 1000;
const BOOTSTRAP_TIMEOUT_MS = 10_000;
const VERSION_KEY_PREFIX = "adlist:data:";
const encoder = new TextEncoder();

// 从版本 key（adlist:data:<sha256>）中取出哈希；格式不符返回 null。
function hashFromVersionKey(version: string): string | null {
  if (!version.startsWith(VERSION_KEY_PREFIX)) return null;
  const hash = version.slice(VERSION_KEY_PREFIX.length);
  return /^[0-9a-f]{64}$/.test(hash) ? hash : null;
}

export interface AdBlockData {
  version: string;
  data: Uint8Array;
  checkedAt: number;
}

export interface AdBlockLists {
  block: AdBlockData | null;
  allow: ReadonlySet<string>;
  checkedAt: number;
}

export type DomainClass = "allow" | "block" | "none";

let cachedLists: AdBlockLists | null = null;
let loadPromise: Promise<AdBlockLists | null> | null = null;
let bootstrapPromise: Promise<"updated" | "unchanged"> | null = null;
let lastBootstrapFailureAt = 0;

function isDomainByte(value: number): boolean {
  return (
    value === 0x2d ||
    value === 0x2e ||
    value === 0x5f ||
    (value >= 0x30 && value <= 0x39) ||
    (value >= 0x61 && value <= 0x7a)
  );
}

function normalizeDomain(value: string): string | null {
  const domain = value.trim().toLowerCase().replace(/\.$/, "");
  if (domain.length === 0 || domain.length > 253) return null;
  // 逐字符校验（等价于 /^[a-z0-9_-]+(\.[a-z0-9_-]+)*$/），比正则快数倍：
  // 更新管线要处理 10 万+ 行
  let previousDot = true; // 首字符视同跟在点后，禁止空标签
  for (let i = 0; i < domain.length; i += 1) {
    const c = domain.charCodeAt(i);
    if (c === 46) {
      if (previousDot) return null;
      previousDot = true;
    } else if (isDomainByte(c)) {
      previousDot = false;
    } else {
      return null;
    }
  }
  if (previousDot) return null;
  return domain;
}

// 下载源的原始文本 → 规范化（去注释/大小写/重复，剥 BOM/CRLF）→ 字节序排序
export function normalizeDomainList(text: string): string[] {
  const stripped = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const seen = new Set<string>();
  for (const rawLine of stripped.split("\n")) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith("#") || line.startsWith("!")) continue;
    const domain = normalizeDomain(line);
    if (domain !== null) seen.add(domain);
  }
  return [...seen].sort();
}

function compareAdLines(
  data: Uint8Array,
  leftStart: number,
  leftEnd: number,
  rightStart: number,
  rightEnd: number
): number {
  const length = Math.min(leftEnd - leftStart, rightEnd - rightStart);
  for (let i = 0; i < length; i += 1) {
    const left = data[leftStart + i] ?? 0;
    const right = data[rightStart + i] ?? 0;
    if (left !== right) return left < right ? -1 : 1;
  }
  const leftLength = leftEnd - leftStart;
  const rightLength = rightEnd - rightStart;
  return leftLength === rightLength ? 0 : leftLength < rightLength ? -1 : 1;
}

// 校验存储形态：单区域、LF 分隔、无 CR、仅 LDH 字符、严格递增。返回条目数。
export function inspectAdData(data: Uint8Array): number {
  if (data.length < MIN_AD_BYTES || data.length > MAX_AD_BYTES) {
    throw new Error("adlist_size_invalid");
  }
  let lineStart = 0;
  let previousStart = -1;
  let previousEnd = -1;
  let count = 0;
  while (lineStart < data.length) {
    let rawEnd = lineStart;
    while (rawEnd < data.length && data[rawEnd] !== 10) rawEnd += 1;
    const lineEnd = rawEnd;
    if (lineEnd <= lineStart) throw new Error("adlist_empty_line");
    for (let i = lineStart; i < lineEnd; i += 1) {
      if (!isDomainByte(data[i] ?? 0)) throw new Error("adlist_invalid_char");
    }
    if (previousStart >= 0) {
      const comparison = compareAdLines(
        data,
        previousStart,
        previousEnd,
        lineStart,
        lineEnd
      );
      if (comparison >= 0) throw new Error("adlist_not_strictly_sorted");
    }
    count += 1;
    previousStart = lineStart;
    previousEnd = lineEnd;
    lineStart = rawEnd < data.length ? rawEnd + 1 : data.length;
  }
  if (count === 0) throw new Error("adlist_missing_entries");
  return count;
}

// 域名或其任意父后缀是否在列表中（与拦截列表"含子域"语义一致）
function matchesSuffixInBytes(data: Uint8Array, qname: string): boolean {
  const target = encoder.encode(qname);
  let start = 0;
  while (start < target.length) {
    if (binarySearchRegion(data, 0, data.length, 0, target, start)) return true;
    let dot = start;
    while (dot < target.length && target[dot] !== 46) dot += 1;
    if (dot >= target.length) break;
    start = dot + 1;
  }
  return false;
}

// 白名单优先：qname 的任意后缀命中白名单即放行，
// 否则任意后缀命中黑名单才拦截（与拦截列表"含子域"语义一致）。
export function classifyDomain(lists: AdBlockLists, qname: string): DomainClass {
  const lower = qname.toLowerCase();
  let start = 0;
  while (start < lower.length) {
    if (lists.allow.has(lower.slice(start))) return "allow";
    const dot = lower.indexOf(".", start);
    if (dot < 0) break;
    start = dot + 1;
  }
  if (lists.block !== null && matchesSuffixInBytes(lists.block.data, lower)) {
    return "block";
  }
  return "none";
}

function parseDomainSet(value: string, into: Set<string>): void {
  for (const part of value.split(/[\s,;]+/)) {
    const domain = normalizeDomain(part);
    if (domain !== null) into.add(domain);
  }
}

async function loadAllowlist(env: Env): Promise<ReadonlySet<string>> {
  const allow = new Set<string>();
  parseDomainSet(env.ADBLOCK_ALLOWLIST ?? "", allow);
  try {
    const stored = await env.RULES_KV.get(ADLIST_ALLOWLIST_KEY, "text");
    if (stored !== null) parseDomainSet(stored, allow);
  } catch {
    // KV 读取失败时保留环境变量里的白名单。
  }
  return allow;
}

async function readAdManifest(env: Env): Promise<RuleManifest | null> {
  const manifest = await env.RULES_KV.get<RuleManifest>(ADLIST_MANIFEST_KEY, "json");
  if (
    manifest === null ||
    typeof manifest.active !== "string" ||
    (manifest.previous !== null && typeof manifest.previous !== "string") ||
    typeof manifest.sha256 !== "string" ||
    !Number.isInteger(manifest.size) ||
    manifest.size < MIN_AD_BYTES ||
    manifest.size > MAX_AD_BYTES
  ) {
    return null;
  }
  return manifest;
}

// 版本 key 形如 adlist:data:<sha256>，哈希即数据的完整性凭证。
// 加载时用 sha256 校验（硬件加速，约 2ms/2MB）替代全量扫描校验，
// 因为内容格式已在更新入库前由 inspectAdData 把过关。
async function loadAdVersion(
  env: Env,
  version: string,
  expectedHash: string | null,
  now: number
): Promise<AdBlockData | null> {
  const buffer = await env.RULES_KV.get(version, "arrayBuffer");
  if (buffer === null) return null;
  if (expectedHash !== null && (await sha256Hex(buffer)) !== expectedHash) {
    return null;
  }
  return { version, data: new Uint8Array(buffer), checkedAt: now };
}

async function refreshLists(
  env: Env,
  now: number,
  force: boolean
): Promise<AdBlockLists | null> {
  if (!force && cachedLists !== null && now - cachedLists.checkedAt < AD_RECHECK_MS) {
    return cachedLists;
  }
  try {
    const allow = await loadAllowlist(env);
    const manifest = await readAdManifest(env);
    if (manifest === null) {
      const block = cachedLists?.block ?? null;
      cachedLists = { block, allow, checkedAt: now };
      return cachedLists;
    }
    let block = cachedLists?.block ?? null;
    if (block === null || block.version !== manifest.active) {
      const active = await loadAdVersion(env, manifest.active, manifest.sha256, now);
      if (active !== null) {
        block = active;
      } else if (manifest.previous !== null) {
        const previous = await loadAdVersion(
          env,
          manifest.previous,
          hashFromVersionKey(manifest.previous),
          now
        );
        if (previous !== null) block = previous;
      }
      if (block !== null) block = { ...block, checkedAt: now };
    } else {
      block = { ...block, checkedAt: now };
    }
    cachedLists = { block, allow, checkedAt: now };
    return cachedLists;
  } catch {
    return cachedLists;
  }
}

export async function getAdLists(
  env: Env,
  now = Date.now(),
  force = false
): Promise<AdBlockLists | null> {
  if (loadPromise !== null) return loadPromise;
  loadPromise = refreshLists(env, now, force).finally(() => {
    loadPromise = null;
  });
  return loadPromise;
}

export async function updateAdList(
  env: Env,
  fetcher: typeof fetch = fetch
): Promise<"updated" | "unchanged"> {
  const url = env.ADBLOCK_LIST_URL?.trim() || DEFAULT_ADBLOCK_LIST_URL;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), BOOTSTRAP_TIMEOUT_MS);
  let response: Response;
  try {
    response = await fetcher(url, {
      method: "GET",
      redirect: "manual",
      signal: controller.signal,
      headers: { Accept: "text/plain" }
    });
  } finally {
    clearTimeout(timeout);
  }
  if (!response.ok) throw new Error("adlist_download_status");
  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  if (contentType.includes("text/html")) throw new Error("adlist_download_html");
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null) {
    const parsedLength = Number(declaredLength);
    if (!Number.isFinite(parsedLength) || parsedLength > MAX_AD_BYTES) {
      throw new Error("adlist_download_too_large");
    }
  }

  const text = await response.text();
  if (text.length > MAX_AD_BYTES) throw new Error("adlist_download_too_large");
  const merged = new Set<string>(normalizeDomainList(text));
  // 用户自定义补充拦截：并入后再统一排序（anti-AD 出于防误伤会豁免部分域名）
  parseDomainSet(env.ADBLOCK_EXTRA_BLOCKLIST ?? "", merged);
  if (merged.size === 0) throw new Error("adlist_empty");
  const domains = [...merged].sort();
  const data = encoder.encode(domains.join("\n"));
  inspectAdData(data);
  const buffer = toArrayBuffer(data);
  const sha256 = await sha256Hex(buffer);
  const version = `${VERSION_KEY_PREFIX}${sha256}`;
  const oldManifest = await readAdManifest(env);
  if (
    oldManifest !== null &&
    oldManifest.active === version &&
    oldManifest.size === data.byteLength
  ) {
    return "unchanged";
  }

  await env.RULES_KV.put(version, buffer);
  const stored = await env.RULES_KV.get(version, "arrayBuffer");
  if (
    stored === null ||
    stored.byteLength !== data.byteLength ||
    (await sha256Hex(stored)) !== sha256
  ) {
    throw new Error("adlist_kv_verification_failed");
  }

  const previous =
    oldManifest === null
      ? null
      : oldManifest.active === version
        ? oldManifest.previous
        : oldManifest.active;
  const manifest: RuleManifest = {
    active: version,
    previous,
    sha256,
    size: data.byteLength,
    updatedAt: new Date().toISOString()
  };
  await env.RULES_KV.put(ADLIST_MANIFEST_KEY, JSON.stringify(manifest));

  const obsolete = oldManifest?.previous;
  if (obsolete !== undefined && obsolete !== null && obsolete !== version && obsolete !== previous) {
    try {
      await env.RULES_KV.delete(obsolete);
    } catch {
      // 旧版本清理失败不影响已经完成的原子切换。
    }
  }
  const allow = cachedLists?.allow ?? (await loadAllowlist(env));
  cachedLists = {
    block: { version, data, checkedAt: Date.now() },
    allow,
    checkedAt: Date.now()
  };
  return "updated";
}

export async function ensureAdLists(env: Env): Promise<AdBlockLists | null> {
  const current = await getAdLists(env);
  if (current !== null && current.block !== null) return current;
  if (lastBootstrapFailureAt !== 0 && Date.now() - lastBootstrapFailureAt < BOOTSTRAP_RETRY_MS) {
    return current;
  }
  if (bootstrapPromise === null) {
    bootstrapPromise = updateAdList(env)
      .catch((error: unknown) => {
        lastBootstrapFailureAt = Date.now();
        throw error;
      })
      .finally(() => {
        bootstrapPromise = null;
      });
  }
  try {
    await bootstrapPromise;
  } catch {
    console.warn("adlist_bootstrap_failed");
    return getAdLists(env, Date.now(), true);
  }
  return getAdLists(env, Date.now(), true);
}

export function resetAdListCacheForTest(): void {
  cachedLists = null;
  loadPromise = null;
  bootstrapPromise = null;
  lastBootstrapFailureAt = 0;
}

