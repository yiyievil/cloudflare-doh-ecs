// 拦截效果统计：isolate 内存计数，低频快照到 KV（按 isolate 分 key 避免写冲突），
// /stats 读取时合并。只记录聚合计数与被拦截域名，不落完整查询日志，与项目隐私原则一致。
import type { Env, WaitUntil } from "./types";

const STATS_PREFIX = "stats:";
const STATS_FLUSH_INTERVAL_MS = 15 * 60 * 1000;
const STATS_TOP_LIMIT = 50;
const STATS_TOP_MAP_LIMIT = 200;
const STATS_MAX_AGE_DAYS = 31;

interface StatsState {
  isolateId: string;
  total: number;
  blocked: number;
  top: Map<string, number>;
  cacheHits: number;
  staleServed: number;
  upstreamMs: number;
  upstreamCount: number;
  lastFlushAt: number;
  dirty: boolean;
}

const state: StatsState = {
  isolateId: crypto.randomUUID(),
  total: 0,
  blocked: 0,
  top: new Map<string, number>(),
  cacheHits: 0,
  staleServed: 0,
  upstreamMs: 0,
  upstreamCount: 0,
  lastFlushAt: 0,
  dirty: false
};

const noStoreHeaders: Record<string, string> = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff"
};

export function recordQuery(): void {
  state.total += 1;
  state.dirty = true;
}

export function recordBlocked(domain: string): void {
  state.blocked += 1;
  if (state.top.size < STATS_TOP_MAP_LIMIT || state.top.has(domain)) {
    state.top.set(domain, (state.top.get(domain) ?? 0) + 1);
  }
  state.dirty = true;
}

export function recordCacheHit(stale = false): void {
  state.cacheHits += 1;
  if (stale) state.staleServed += 1;
  state.dirty = true;
}

export function recordUpstreamLatency(ms: number): void {
  state.upstreamMs += ms;
  state.upstreamCount += 1;
  state.dirty = true;
}

function dateKey(now = Date.now()): string {
  return new Date(now).toISOString().slice(0, 10);
}

function topEntries(map: Map<string, number>): [string, number][] {
  return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, STATS_TOP_LIMIT);
}

// 把当前 isolate 的计数写入 KV。key 按「日期:isolate」隔离，多 isolate 写入互不覆盖。
export async function flushStats(env: Env): Promise<void> {
  if (!state.dirty) return;
  const key = `${STATS_PREFIX}${dateKey()}:${state.isolateId}`;
  const payload = {
    total: state.total,
    blocked: state.blocked,
    cacheHits: state.cacheHits,
    staleServed: state.staleServed,
    upstreamMs: Math.round(state.upstreamMs),
    upstreamCount: state.upstreamCount,
    top: topEntries(state.top),
    updatedAt: new Date().toISOString()
  };
  await env.RULES_KV.put(key, JSON.stringify(payload));
  state.dirty = false;
}

export function maybeFlushStats(env: Env, ctx?: WaitUntil): void {
  if (!state.dirty || ctx === undefined) return;
  const now = Date.now();
  if (now - state.lastFlushAt < STATS_FLUSH_INTERVAL_MS) return;
  state.lastFlushAt = now;
  ctx.waitUntil(flushStats(env).catch(() => undefined));
}

interface StatsPage {
  keys: { name: string }[];
  list_complete: boolean;
  cursor?: string;
}

async function listStatsKeys(env: Env): Promise<string[]> {
  const names: string[] = [];
  let cursor: string | null = null;
  do {
    const page: StatsPage = await env.RULES_KV.list({
      prefix: STATS_PREFIX,
      cursor
    });
    for (const key of page.keys) names.push(key.name);
    cursor = page.list_complete ? null : (page.cursor ?? null);
  } while (cursor !== null);
  return names;
}

export async function handleStatsRequest(request: Request, env: Env): Promise<Response> {
  const token = env.STATS_TOKEN;
  if (token === undefined || token.length === 0) {
    return new Response(null, { status: 404, headers: noStoreHeaders });
  }
  const url = new URL(request.url);
  const provided = url.searchParams.get("token") ?? request.headers.get("x-stats-token");
  if (provided !== token) {
    return new Response(null, { status: 404, headers: noStoreHeaders });
  }

  const totals = { total: 0, blocked: 0, cacheHits: 0, staleServed: 0, upstreamMs: 0, upstreamCount: 0, isolates: 0 };
  const top = new Map<string, number>();
  for (const name of await listStatsKeys(env)) {
    let raw: unknown = null;
    try {
      raw = await env.RULES_KV.get(name, "json");
    } catch {
      continue; // 单条快照损坏不影响整体聚合。
    }
    if (raw === null || typeof raw !== "object") continue;
    const entry = raw as {
      total?: unknown; blocked?: unknown; cacheHits?: unknown; staleServed?: unknown;
      upstreamMs?: unknown; upstreamCount?: unknown; top?: unknown;
    };
    if (typeof entry.total === "number") totals.total += entry.total;
    if (typeof entry.blocked === "number") totals.blocked += entry.blocked;
    if (typeof entry.cacheHits === "number") totals.cacheHits += entry.cacheHits;
    if (typeof entry.staleServed === "number") totals.staleServed += entry.staleServed;
    if (typeof entry.upstreamMs === "number") totals.upstreamMs += entry.upstreamMs;
    if (typeof entry.upstreamCount === "number") totals.upstreamCount += entry.upstreamCount;
    if (Array.isArray(entry.top)) {
      for (const item of entry.top) {
        if (Array.isArray(item) && typeof item[0] === "string" && typeof item[1] === "number") {
          top.set(item[0], (top.get(item[0]) ?? 0) + item[1]);
        }
      }
    }
    totals.isolates += 1;
  }
  const body = JSON.stringify(
    {
      ...totals,
      upstreamAvgMs:
        totals.upstreamCount > 0 ? Math.round(totals.upstreamMs / totals.upstreamCount) : 0,
      cacheHitRate: totals.total > 0 ? Math.round((totals.cacheHits / totals.total) * 100) : 0,
      top: topEntries(top)
    },
    null,
    2
  );
  return new Response(body, {
    status: 200,
    headers: { ...noStoreHeaders, "Content-Type": "application/json" }
  });
}

// Cron 调用：清理超过保留期的统计快照。
export async function cleanupStats(env: Env): Promise<number> {
  const cutoff = new Date(Date.now() - STATS_MAX_AGE_DAYS * 86_400_000)
    .toISOString()
    .slice(0, 10);
  let deleted = 0;
  for (const name of await listStatsKeys(env)) {
    const date = name.slice(STATS_PREFIX.length, STATS_PREFIX.length + 10);
    if (date < cutoff) {
      try {
        await env.RULES_KV.delete(name);
        deleted += 1;
      } catch {
        // 单条删除失败不影响其余清理。
      }
    }
  }
  return deleted;
}

export function resetStatsForTest(): void {
  state.total = 0;
  state.blocked = 0;
  state.top = new Map<string, number>();
  state.cacheHits = 0;
  state.staleServed = 0;
  state.upstreamMs = 0;
  state.upstreamCount = 0;
  state.lastFlushAt = 0;
  state.dirty = false;
}
