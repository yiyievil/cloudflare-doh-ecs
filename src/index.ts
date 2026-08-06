import { toArrayBuffer } from "./binary";
import { buildDnsError, DnsFormatError, parseDnsMessage, validateUpstreamResponse } from "./dns";
import { rewriteEcs } from "./ecs";
import { clientIpFromSingleHeader, clientIpFromXff, subnetForEcs } from "./ip";
import { ensureRules, isDomesticDomain, updateRules } from "./rules";
import { readConfig, type WorkerConfig } from "./config";
import type { Env } from "./types";

const MAX_REQUEST_BYTES = 4096;
const MAX_RESPONSE_BYTES = 65535;
const UPSTREAM_TIMEOUT_MS = 2000;
const ECS_IPV4_PREFIX = 24;
const ECS_IPV6_PREFIX = 56;
const DNS_CONTENT_TYPE = "application/dns-message";

// 内存级 DNS 响应缓存，减少重复上游查询
const DNS_CACHE_MAX_SIZE = 512;
const DNS_CACHE_TTL_MS = 60_000;
interface DnsCacheEntry {
  body: Uint8Array;
  expiresAt: number;
}
const dnsCache = new Map<string, DnsCacheEntry>();

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

function dnsCacheKey(query: Uint8Array): string {
  // 跳过前 2 字节事务 ID，用 flags + question 部分作为缓存键
  const start = 2;
  const len = Math.min(query.length - start, 30);
  let key = "";
  for (let i = 0; i < len; i += 1) key += (query[start + i] ?? 0).toString(16).padStart(2, "0");
  return key;
}

// 从缓存生成响应：必须把响应报文的 2 字节事务 ID 替换为当前请求的事务 ID，
// 否则客户端会因 ID 不匹配而丢弃响应。
function dnsCacheGet(query: Uint8Array): Uint8Array | null {
  const key = dnsCacheKey(query);
  const entry = dnsCache.get(key);
  if (entry === undefined) return null;
  if (Date.now() > entry.expiresAt) {
    dnsCache.delete(key);
    return null;
  }
  const body = entry.body.slice();
  if (body.length >= 2 && query.length >= 2) {
    body[0] = query[0] ?? 0;
    body[1] = query[1] ?? 0;
  }
  return body;
}

function dnsCacheSet(query: Uint8Array, body: Uint8Array): void {
  const key = dnsCacheKey(query);
  if (dnsCache.size >= DNS_CACHE_MAX_SIZE) {
    // 简单淘汰：删除最早插入的条目
    const firstKey = dnsCache.keys().next().value;
    if (firstKey !== undefined) dnsCache.delete(firstKey);
  }
  dnsCache.set(key, { body: body.slice(), expiresAt: Date.now() + DNS_CACHE_TTL_MS });
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

async function fetchUpstream(url: string, query: Uint8Array): Promise<Uint8Array> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
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
  }
}

async function handleDns(request: Request, env: Env, config: WorkerConfig): Promise<Response> {
  const readResult = await readDnsRequest(request, config);
  if (readResult instanceof Response) return readResult;
  const originalQuery = readResult;

  let parsed;
  try {
    parsed = parseDnsMessage(originalQuery);
  } catch {
    return dnsResponse(buildDnsError(originalQuery, 1));
  }

  // 先查内存缓存（会替换事务 ID 为当前请求的 ID）
  const cached = dnsCacheGet(originalQuery);
  if (cached !== null) {
    return dnsResponse(cached, 200, 30);
  }

  let forwardedQuery: Uint8Array;
  try {
    const ip =
      clientIpFromXff(request.headers.get("x-forwarded-for")) ??
      clientIpFromSingleHeader(request.headers.get("cf-connecting-ip"));
    const subnet = subnetForEcs(ip, ECS_IPV4_PREFIX, ECS_IPV6_PREFIX);
    forwardedQuery = rewriteEcs(originalQuery, parsed, subnet);
  } catch (error) {
    if (error instanceof DnsFormatError) {
      return dnsResponse(buildDnsError(originalQuery, 1, parsed.question));
    }
    return dnsResponse(buildDnsError(originalQuery, 2, parsed.question));
  }

  let domestic = false;
  const ruleName = parsed.question.name.ruleName;
  if (ruleName !== null) {
    // GitHub 相关域名强制走国内 DNS，获取国内可访问的 IP
    if (isForcedDomestic(ruleName)) {
      domestic = true;
    } else {
      const rules = await ensureRules(env);
      domestic = rules !== null && isDomesticDomain(rules, ruleName);
    }
  }
  const upstreams = domestic ? config.domesticUrls : config.globalUrls;
  const group = domestic ? "domestic" : "global";
  let upstreamIndex = 0;
  for (const upstream of upstreams) {
    const role = upstreamIndex === 0 ? "primary" : "fallback";
    upstreamIndex += 1;
    try {
      const upstreamBody = await fetchUpstream(upstream, forwardedQuery);
      const upstreamInfo = validateUpstreamResponse(upstreamBody, parsed);
      if ((upstreamInfo.flags & 0x000f) === 2) {
        logUpstreamFailure(group, role, { reason: "dns_servfail" });
        continue;
      }
      // 缓存成功响应
      dnsCacheSet(originalQuery, upstreamBody);
      return dnsResponse(upstreamBody, 200, 30);
    } catch (error) {
      logUpstreamFailure(group, role, upstreamFailureDiagnostic(error));
      // 仅在当前国内或国外组内尝试下一上游，不进行跨组回退。
    }
  }
  return dnsResponse(buildDnsError(originalQuery, 2, parsed.question));
}

export async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
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
  return handleDns(request, env, config);
}

export default {
  fetch(request: Request, env: Env): Promise<Response> {
    return handleRequest(request, env);
  },

  scheduled(
    _controller: ScheduledController,
    env: Env,
    ctx: ExecutionContext
  ): void {
    ctx.waitUntil(
      updateRules(env).then(
        () => undefined,
        () => undefined
      )
    );
  }
} satisfies ExportedHandler<Env>;
