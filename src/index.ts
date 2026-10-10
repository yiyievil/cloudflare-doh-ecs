import { toArrayBuffer } from "./binary";
import {
  buildDnsError,
  buildSinkholeResponse,
  cnameChainTargets,
  DnsFormatError,
  dnssecDo,
  minAnswerTtl,
  parseDnsMessage,
  validateUpstreamResponse,
  type DnsMessageInfo,
  type DnsQuestion
} from "./dns";
import { rewriteEcs } from "./ecs";
import { clientIpFromSingleHeader, clientIpFromXff, subnetForEcs, type EcsSubnet } from "./ip";
import { ensureRules, isDomesticDomain, updateRules } from "./rules";
import { classifyDomain, ensureAdLists, getAdLists, updateAdList, type AdBlockLists } from "./adlist";
import {
  cleanupStats,
  flushStats,
  handleStatsRequest,
  maybeFlushStats,
  recordBlocked,
  recordCacheHit,
  recordQuery,
  recordUpstreamLatency,
  resetStatsForTest
} from "./stats";
import { readConfig, type WorkerConfig } from "./config";
import { resetAdListCacheForTest } from "./adlist";
import type { Env, WaitUntil } from "./types";

const MAX_REQUEST_BYTES = 4096;
const MAX_RESPONSE_BYTES = 65535;
const UPSTREAM_TIMEOUT_MS = 2000;
const ECS_IPV4_PREFIX = 24;
const ECS_IPV6_PREFIX = 56;
const DNS_CONTENT_TYPE = "application/dns-message";
const CACHE_MIN_TTL = 30;
const CACHE_MAX_TTL = 1800;
const CACHE_DEFAULT_TTL = 60;
// 过期后仍可立即应答的窗口；应答同时后台刷新（stale-while-revalidate）
const STALE_WINDOW_MS = 30 * 60 * 1000;
// 主路上游超过该时长未应答即启动备路对冲，先到先用
const HEDGE_DELAY_MS = 250;

// 内存级 DNS 响应缓存，减少重复上游查询
const DNS_CACHE_MAX_SIZE = 4096;
interface DnsCacheEntry {
  body: Uint8Array;
  expiresAt: number;
  staleUntil: number;
  maxAge: number;
}
const dnsCache = new Map<string, DnsCacheEntry>();
const refreshInflight = new Set<string>();

// 需强制走国内 DNS 的域名（国内可访问性更好），避免被分流到国外上游
const FORCE_DOMESTIC_SUFFIXES = [
  "github.com",
  "github.io",
  "githubapp.com",
  "githubassets.com",
  "githubusercontent.com",
  "githubcopilot.com",
  "github.blog",
  "github.dev",
  "raw.githubusercontent.com",
  "objects.githubusercontent.com",
  "codeload.github.com",
  "api.github.com",
  "avatars.githubusercontent.com"
];

function isForcedDomestic(ruleName: string): boolean {
  const lower = ruleName.toLowerCase();
  return FORCE_DOMESTIC_SUFFIXES.some((suffix) =>
    lower === suffix || lower.endsWith("." + suffix)
  );
}

// 缓存键必须覆盖完整 question 与 ECS 子网：截断键会让长域名互相污染，
// 且不同子网客户端会共享彼此的 CDN 解析结果。
function dnsCacheKey(parsed: DnsMessageInfo, doBit: boolean, subnetKey: string): string {
  const ruleName = parsed.question.name.ruleName;
  if (ruleName === null || ruleName.length === 0) return "";
  return `${ruleName}|${parsed.question.type}|${parsed.question.class}|${doBit ? 1 : 0}|${subnetKey}`;
}

function subnetKeyOf(subnet: EcsSubnet | null): string {
  if (subnet === null) return "-";
  const usedBytes = Math.ceil(subnet.prefixLength / 8);
  let hex = "";
  for (let i = 0; i < usedBytes; i += 1) {
    hex += (subnet.network[i] ?? 0).toString(16).padStart(2, "0");
  }
  return `${subnet.family}/${subnet.prefixLength}/${hex}`;
}

// 从缓存生成响应：必须把响应报文的 2 字节事务 ID 替换为当前请求的事务 ID，
// 否则客户端会因 ID 不匹配而丢弃响应。
function withTransactionId(body: Uint8Array, query: Uint8Array): Uint8Array {
  const copy = body.slice();
  if (copy.length >= 2 && query.length >= 2) {
    copy[0] = query[0] ?? 0;
    copy[1] = query[1] ?? 0;
  }
  return copy;
}

function dnsCacheSet(key: string, body: Uint8Array, ttlSeconds: number): void {
  if (key === "") return;
  if (dnsCache.size >= DNS_CACHE_MAX_SIZE) {
    // 简单淘汰：删除最早插入的条目
    const firstKey = dnsCache.keys().next().value;
    if (firstKey !== undefined) dnsCache.delete(firstKey);
  }
  const expiresAt = Date.now() + ttlSeconds * 1000;
  dnsCache.set(key, {
    body: body.slice(),
    expiresAt,
    staleUntil: expiresAt + STALE_WINDOW_MS,
    maxAge: ttlSeconds
  });
}

function resetDnsCacheForTest(): void {
  dnsCache.clear();
  refreshInflight.clear();
}

class UpstreamFailure extends Error {
  constructor(
    readonly reason: string,
    readonly detail?: string
  ) {
    super(reason);
    this.name = "UpstreamFailure";
  }
}

interface UpstreamFailureDiagnostic {
  reason: string;
  detail?: string;
}

function safeFetchErrorDetail(error: unknown): string {
  if (!(error instanceof Error)) return `non_error:${typeof error}`;
  return `${error.name}: ${error.message}`
    .replace(/https:\/\/[^\s"'<>]+/gi, "[url]")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 240);
}

function upstreamFailureDiagnostic(error: unknown): UpstreamFailureDiagnostic {
  if (error instanceof UpstreamFailure) {
    return error.detail === undefined
      ? { reason: error.reason }
      : { reason: error.reason, detail: error.detail };
  }
  if (error instanceof DnsFormatError) return { reason: `dns_${error.message}` };
  return { reason: "unexpected_error" };
}

function logUpstreamFailure(
  group: "domestic" | "global",
  role: "primary" | "fallback",
  diagnostic: UpstreamFailureDiagnostic
): void {
  // 不记录查询域名、DNS 报文、客户端地址或自定义上游 URL。
  console.warn("doh_upstream_failed", { group, role, ...diagnostic });
}

function emptyResponse(status: number, extraHeaders?: HeadersInit): Response {
  const headers = new Headers(extraHeaders);
  headers.set("Cache-Control", "no-store");
  headers.set("X-Content-Type-Options", "nosniff");
  return new Response(null, { status, headers });
}

function dnsResponse(body: Uint8Array, status = 200, cacheMaxAge = 0): Response {
  const headers: Record<string, string> = {
    "Content-Type": DNS_CONTENT_TYPE,
    "X-Content-Type-Options": "nosniff"
  };
  headers["Cache-Control"] = cacheMaxAge > 0 ? `public, max-age=${cacheMaxAge}` : "no-store";
  return new Response(toArrayBuffer(body), { status, headers });
}

function contentTypeIsDns(request: Request): boolean {
  const value = request.headers.get("content-type");
  if (value === null) return false;
  return value.split(";", 1)[0]?.trim().toLowerCase() === DNS_CONTENT_TYPE;
}

function decodeBase64Url(value: string): Uint8Array | null {
  if (
    value.length === 0 ||
    value.length > Math.ceil(MAX_REQUEST_BYTES * 4 / 3) + 4 ||
    !/^[A-Za-z0-9_-]+={0,2}$/.test(value) ||
    value.length % 4 === 1
  ) {
    return null;
  }
  const unpadded = value.replace(/=+$/, "");
  const padding = "=".repeat((4 - (unpadded.length % 4)) % 4);
  try {
    const decoded = atob(unpadded.replace(/-/g, "+").replace(/_/g, "/") + padding);
    if (decoded.length > MAX_REQUEST_BYTES) return null;
    const output = new Uint8Array(decoded.length);
    for (let i = 0; i < decoded.length; i += 1) output[i] = decoded.charCodeAt(i);
    return output;
  } catch {
    return null;
  }
}

async function readDnsRequest(request: Request, config: WorkerConfig): Promise<Response | Uint8Array> {
  const url = new URL(request.url);
  if (url.pathname !== config.path) return emptyResponse(404);

  if (request.method === "GET") {
    const values = url.searchParams.getAll("dns");
    if (values.length !== 1 || [...url.searchParams.keys()].some((key) => key !== "dns")) {
      return emptyResponse(400);
    }
    const decoded = decodeBase64Url(values[0] ?? "");
    return decoded ?? emptyResponse(400);
  }

  if (request.method === "POST") {
    if (url.search !== "") return emptyResponse(400);
    if (!contentTypeIsDns(request)) return emptyResponse(415);
    const declaredLength = request.headers.get("content-length");
    if (declaredLength !== null) {
      const parsed = Number(declaredLength);
      if (!Number.isFinite(parsed) || parsed < 0 || parsed > MAX_REQUEST_BYTES) {
        return emptyResponse(413);
      }
    }
    const buffer = await request.arrayBuffer();
    if (buffer.byteLength > MAX_REQUEST_BYTES) return emptyResponse(413);
    if (buffer.byteLength === 0) return emptyResponse(400);
    return new Uint8Array(buffer);
  }

  return emptyResponse(405, { Allow: "GET, POST" });
}

async function fetchUpstream(url: string, query: Uint8Array, externalSignal?: AbortSignal): Promise<Uint8Array> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
  const forwardAbort = (): void => controller.abort();
  externalSignal?.addEventListener("abort", forwardAbort, { once: true });
  try {
    let response: Response;
    try {
      response = await fetch(url, {
        method: "POST",
        redirect: "manual",
        signal: controller.signal,
        headers: {
          Accept: DNS_CONTENT_TYPE,
          "Content-Type": DNS_CONTENT_TYPE
        },
        body: toArrayBuffer(query)
      });
    } catch (error) {
      throw new UpstreamFailure(
        controller.signal.aborted ? "timeout" : "network_error",
        safeFetchErrorDetail(error)
      );
    }
    if (!response.ok) throw new UpstreamFailure(`http_status_${response.status}`);
    const type = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
    if (type !== DNS_CONTENT_TYPE) throw new UpstreamFailure("invalid_content_type");
    const declaredLength = response.headers.get("content-length");
    if (declaredLength !== null && Number(declaredLength) > MAX_RESPONSE_BYTES) {
      throw new UpstreamFailure("response_too_large");
    }
    let buffer: ArrayBuffer;
    try {
      buffer = await response.arrayBuffer();
    } catch (error) {
      throw new UpstreamFailure(
        controller.signal.aborted ? "timeout" : "response_read_error",
        safeFetchErrorDetail(error)
      );
    }
    if (buffer.byteLength < 12 || buffer.byteLength > MAX_RESPONSE_BYTES) {
      throw new UpstreamFailure("invalid_response_size");
    }
    return new Uint8Array(buffer);
  } finally {
    clearTimeout(timeout);
    externalSignal?.removeEventListener("abort", forwardAbort);
  }
}

interface UpstreamAttemptOutcome {
  ok: boolean;
  body?: Uint8Array;
  info?: DnsMessageInfo;
  reason?: string;
  detail?: string;
}

async function attemptUpstream(
  url: string,
  query: Uint8Array,
  parsed: DnsMessageInfo,
  controller: AbortController
): Promise<UpstreamAttemptOutcome> {
  try {
    const upstreamBody = await fetchUpstream(url, query, controller.signal);
    const upstreamInfo = validateUpstreamResponse(upstreamBody, parsed);
    if ((upstreamInfo.flags & 0x000f) === 2) {
      return { ok: false, reason: "dns_servfail" };
    }
    return { ok: true, body: upstreamBody, info: upstreamInfo };
  } catch (error) {
    const diagnostic = upstreamFailureDiagnostic(error);
    return diagnostic.detail === undefined
      ? { ok: false, reason: diagnostic.reason }
      : { ok: false, reason: diagnostic.reason, detail: diagnostic.detail };
  }
}

interface UpstreamAnswer {
  body: Uint8Array;
  info: DnsMessageInfo;
  elapsedMs: number;
}

// 对冲请求：主路先发，HEDGE_DELAY_MS 内未应答即启动备路，先到的有效答案获胜，
// 淘汰未决请求。主路快速失败时立即补位，不空等对冲窗口。
async function resolveFromUpstreams(
  group: "domestic" | "global",
  upstreams: readonly [string, string],
  query: Uint8Array,
  parsed: DnsMessageInfo
): Promise<UpstreamAnswer | null> {
  const startedAt = Date.now();
  return await new Promise((resolve) => {
    let settled = false;
    let started = 0;
    let inflight = 0;
    const controllers: AbortController[] = [];
    const hedge = upstreams.length > 1
      ? setTimeout(() => {
          if (!settled) startNext();
        }, HEDGE_DELAY_MS)
      : undefined;

    const finish = (answer: UpstreamAnswer | null): void => {
      if (settled) return;
      settled = true;
      if (hedge !== undefined) clearTimeout(hedge);
      for (const controller of controllers) controller.abort();
      resolve(answer);
    };

    const startNext = (): void => {
      const url = upstreams[started];
      if (url === undefined) return;
      const role = started === 0 ? "primary" : "fallback";
      started += 1;
      inflight += 1;
      const controller = new AbortController();
      controllers.push(controller);
      void attemptUpstream(url, query, parsed, controller).then((outcome) => {
        inflight -= 1;
        if (settled) return;
        if (outcome.ok && outcome.body !== undefined && outcome.info !== undefined) {
          finish({ body: outcome.body, info: outcome.info, elapsedMs: Date.now() - startedAt });
          return;
        }
        logUpstreamFailure(group, role, {
          reason: outcome.reason ?? "unexpected_error",
          ...(outcome.detail !== undefined ? { detail: outcome.detail } : {})
        });
        // 主路快速失败时立即补位启动下一路；全部失败且无在途请求才判定耗尽
        startNext();
        if (inflight === 0) finish(null);
      });
    };

    startNext();
  });
}

// 按配置生成拦截响应：nxdomain（默认）/ zeroip（A/AAAA 记 sinkhole，其余 NOERROR 空）/ empty
function buildBlockedBody(
  query: Uint8Array,
  config: WorkerConfig,
  question: DnsQuestion
): Uint8Array {
  if (config.adblockResponse === "zeroip") {
    const sinkhole = buildSinkholeResponse(query, question);
    if (sinkhole !== null) return sinkhole;
    return buildDnsError(query, 0, question);
  }
  if (config.adblockResponse === "empty") {
    return buildDnsError(query, 0, question);
  }
  return buildDnsError(query, 3, question);
}

async function determineDomestic(env: Env, parsed: DnsMessageInfo): Promise<boolean> {
  const ruleName = parsed.question.name.ruleName;
  if (ruleName === null) return false;
  if (isForcedDomestic(ruleName)) return true;
  const rules = await ensureRules(env);
  return rules !== null && isDomesticDomain(rules, ruleName);
}

// CNAME 链检查：追踪域名常借品牌域名 CNAME 伪装，逐级核对黑/白名单。
// 链上任一成员命中白名单即整链放行；否则返回第一个命中的黑名单成员。
function firstBlockedCname(
  lists: AdBlockLists,
  info: DnsMessageInfo,
  message: Uint8Array
): string | null {
  const targets = cnameChainTargets(info, message);
  let blocked: string | null = null;
  for (const target of targets) {
    const verdict = classifyDomain(lists, target);
    if (verdict === "allow") return null;
    if (verdict === "block" && blocked === null) blocked = target;
  }
  return blocked;
}

// 过期条目的 stale-while-revalidate：立即用旧值应答后，后台按完整管线重新解析并回填缓存
function kickStaleRefresh(
  cacheKey: string,
  env: Env,
  config: WorkerConfig,
  ctx: WaitUntil,
  originalQuery: Uint8Array,
  parsed: DnsMessageInfo,
  subnet: EcsSubnet | null
): void {
  if (refreshInflight.has(cacheKey)) return;
  refreshInflight.add(cacheKey);
  const task = (async () => {
    try {
      const domestic = await determineDomestic(env, parsed);
      const forwardedQuery = rewriteEcs(originalQuery, parsed, subnet);
      const result = await resolveFromUpstreams(
        domestic ? "domestic" : "global",
        domestic ? config.domesticUrls : config.globalUrls,
        forwardedQuery,
        parsed
      );
      if (result === null) return;
      recordUpstreamLatency(result.elapsedMs);
      const lists = await getAdLists(env);
      if (lists !== null) {
        const chainBlocked = firstBlockedCname(lists, result.info, result.body);
        if (chainBlocked !== null) {
          // 域名在条目存续期间被列入黑名单：撤销缓存
          recordBlocked(chainBlocked);
          dnsCache.delete(cacheKey);
          return;
        }
      }
      const ttl = clampTtl(minAnswerTtl(result.info) ?? CACHE_DEFAULT_TTL);
      dnsCacheSet(cacheKey, result.body, ttl);
    } catch {
      // 后台刷新失败保持静默，旧条目继续可用直到滑出 stale 窗口。
    } finally {
      refreshInflight.delete(cacheKey);
    }
  })();
  ctx.waitUntil(task);
}

function clampTtl(ttl: number): number {
  if (ttl < CACHE_MIN_TTL) return CACHE_MIN_TTL;
  if (ttl > CACHE_MAX_TTL) return CACHE_MAX_TTL;
  return ttl;
}

async function handleDns(
  request: Request,
  env: Env,
  config: WorkerConfig,
  ctx?: WaitUntil
): Promise<Response> {
  const readResult = await readDnsRequest(request, config);
  if (readResult instanceof Response) return readResult;
  const originalQuery = readResult;

  let parsed;
  try {
    parsed = parseDnsMessage(originalQuery);
  } catch {
    return dnsResponse(buildDnsError(originalQuery, 1));
  }
  recordQuery();

  const qname = parsed.question.name.ruleName;
  let adLists: AdBlockLists | null = null;
  if (config.adblockEnabled && qname !== null) {
    adLists = await ensureAdLists(env);
    if (adLists !== null && classifyDomain(adLists, qname) === "block") {
      recordBlocked(qname);
      return dnsResponse(buildBlockedBody(originalQuery, config, parsed.question), 200, CACHE_MIN_TTL);
    }
  }

  let subnet: EcsSubnet | null = null;
  try {
    const ip =
      clientIpFromXff(request.headers.get("x-forwarded-for")) ??
      clientIpFromSingleHeader(request.headers.get("cf-connecting-ip"));
    subnet = subnetForEcs(ip, ECS_IPV4_PREFIX, ECS_IPV6_PREFIX);
  } catch {
    return dnsResponse(buildDnsError(originalQuery, 2, parsed.question));
  }
  const subnetKey = subnetKeyOf(subnet);
  const cacheKey = dnsCacheKey(parsed, dnssecDo(parsed), subnetKey);

  // 缓存命中 / stale-while-revalidate
  const entry = cacheKey === "" ? undefined : dnsCache.get(cacheKey);
  const now = Date.now();
  if (entry !== undefined) {
    if (now <= entry.expiresAt) {
      recordCacheHit();
      return dnsResponse(withTransactionId(entry.body, originalQuery), 200, entry.maxAge);
    }
    if (now <= entry.staleUntil) {
      recordCacheHit(true);
      if (ctx !== undefined) {
        kickStaleRefresh(cacheKey, env, config, ctx, originalQuery, parsed, subnet);
      }
      return dnsResponse(withTransactionId(entry.body, originalQuery), 200);
    }
    dnsCache.delete(cacheKey);
  }

  let forwardedQuery: Uint8Array;
  try {
    forwardedQuery = rewriteEcs(originalQuery, parsed, subnet);
  } catch (error) {
    if (error instanceof DnsFormatError) {
      return dnsResponse(buildDnsError(originalQuery, 1, parsed.question));
    }
    return dnsResponse(buildDnsError(originalQuery, 2, parsed.question));
  }

  const domestic = await determineDomestic(env, parsed);
  const group = domestic ? "domestic" : "global";
  const result = await resolveFromUpstreams(
    group,
    domestic ? config.domesticUrls : config.globalUrls,
    forwardedQuery,
    parsed
  );
  if (result === null) {
    return dnsResponse(buildDnsError(originalQuery, 2, parsed.question));
  }
  recordUpstreamLatency(result.elapsedMs);

  if (adLists !== null) {
    const chainBlocked = firstBlockedCname(adLists, result.info, result.body);
    if (chainBlocked !== null) {
      recordBlocked(chainBlocked);
      return dnsResponse(buildBlockedBody(originalQuery, config, parsed.question), 200, CACHE_MIN_TTL);
    }
  }

  const ttl = clampTtl(minAnswerTtl(result.info) ?? CACHE_DEFAULT_TTL);
  dnsCacheSet(cacheKey, result.body, ttl);
  return dnsResponse(result.body, 200, ttl);
}

export async function handleRequest(request: Request, env: Env, ctx?: WaitUntil): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === "/stats") {
    return handleStatsRequest(request, env);
  }
  const expectedPath = env.DOH_PATH ?? "/doh";

  // 纯 DoH 域名，非 DoH 路径返回提示
  if (url.pathname !== expectedPath) {
    return new Response("DNS-over-HTTPS endpoint. Use /doh with GET ?dns= or POST application/dns-message.", {
      status: 200,
      headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" }
    });
  }

  let config: WorkerConfig;
  try {
    config = readConfig(env);
  } catch {
    let query = new Uint8Array();
    if (request.method === "POST") {
      try {
        const buffer = await request.arrayBuffer();
        if (buffer.byteLength <= MAX_REQUEST_BYTES) query = new Uint8Array(buffer);
      } catch {
        // 配置错误时也只返回 DNS 或空响应，不泄露具体环境变量。
      }
    }
    return dnsResponse(buildDnsError(query, 2));
  }
  const response = await handleDns(request, env, config, ctx);
  maybeFlushStats(env, ctx);
  return response;
}

export async function runScheduledTasks(env: Env): Promise<void> {
  await Promise.allSettled([
    updateRules(env),
    updateAdList(env),
    flushStats(env),
    cleanupStats(env)
  ]);
}

export { resetDnsCacheForTest, resetStatsForTest, resetAdListCacheForTest };

export default {
  fetch(request: Request, env: Env, ctx?: WaitUntil): Promise<Response> {
    return handleRequest(request, env, ctx);
  },

  scheduled(
    _controller: ScheduledController,
    env: Env,
    ctx: ExecutionContext
  ): void {
    ctx.waitUntil(
      runScheduledTasks(env)
    );
  }
} satisfies ExportedHandler<Env>;
