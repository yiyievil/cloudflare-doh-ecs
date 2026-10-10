import { cleanupStats, flushStats, handleStatsRequest, recordBlocked, recordQuery, resetStatsForTest } from "../src/stats";
import { envWithRules, MemoryKv } from "./helpers";

describe("stats", () => {
  beforeEach(() => {
    resetStatsForTest();
  });

  it("is disabled (404) until STATS_TOKEN is configured", async () => {
    const { env } = await envWithRules();
    const disabled = await handleStatsRequest(
      new Request("https://worker.example/stats"),
      env
    );
    expect(disabled.status).toBe(404);
    expect(await disabled.text()).toBe("");
  });

  it("rejects wrong tokens with 404", async () => {
    const { env } = await envWithRules(undefined, {
      overrides: { STATS_TOKEN: "secret" }
    });
    const none = await handleStatsRequest(new Request("https://worker.example/stats"), env);
    expect(none.status).toBe(404);
    const wrong = await handleStatsRequest(
      new Request("https://worker.example/stats?token=nope"),
      env
    );
    expect(wrong.status).toBe(404);
    const header = await handleStatsRequest(
      new Request("https://worker.example/stats", { headers: { "x-stats-token": "nope" } }),
      env
    );
    expect(header.status).toBe(404);
  });

  it("aggregates flushed snapshots and ranks blocked domains", async () => {
    const { env } = await envWithRules(undefined, {
      overrides: { STATS_TOKEN: "secret" }
    });
    recordQuery();
    recordBlocked("doubleclick.net");
    recordQuery();
    recordBlocked("hm.baidu.com");
    recordBlocked("hm.baidu.com");
    await flushStats(env);

    const response = await handleStatsRequest(
      new Request("https://worker.example/stats?token=secret"),
      env
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/json");
    const body = (await response.json()) as {
      total: number;
      blocked: number;
      isolates: number;
      top: [string, number][];
    };
    expect(body.total).toBe(2);
    expect(body.blocked).toBe(3);
    expect(body.isolates).toBe(1);
    expect(body.top[0]).toEqual(["hm.baidu.com", 2]);
  });

  it("flushes into per-isolate keys that merge without overwriting", async () => {
    const { env, kv } = await envWithRules(undefined, {
      overrides: { STATS_TOKEN: "secret" }
    });
    recordQuery();
    recordBlocked("cnzz.com");
    await flushStats(env);

    // 模拟另一个 isolate 的快照
    await kv.put(
      `stats:${new Date().toISOString().slice(0, 10)}:other-isolate`,
      JSON.stringify({ total: 10, blocked: 4, top: [["cnzz.com", 4]] })
    );

    const response = await handleStatsRequest(
      new Request("https://worker.example/stats?token=secret"),
      env
    );
    const body = (await response.json()) as {
      total: number;
      blocked: number;
      isolates: number;
      top: [string, number][];
    };
    expect(body.total).toBe(11);
    expect(body.blocked).toBe(5);
    expect(body.isolates).toBe(2);
    expect(body.top[0]).toEqual(["cnzz.com", 5]);
  });

  it("cleans up snapshots older than the retention window", async () => {
    const { env, kv } = await envWithRules();
    const stale = "stats:2020-01-01:old";
    const fresh = `stats:${new Date().toISOString().slice(0, 10)}:new`;
    await kv.put(stale, JSON.stringify({ total: 1, blocked: 1, top: [] }));
    await kv.put(fresh, JSON.stringify({ total: 1, blocked: 1, top: [] }));

    const deleted = await cleanupStats(env);
    expect(deleted).toBe(1);
    expect(kv.values.has(stale)).toBe(false);
    expect(kv.values.has(fresh)).toBe(true);
  });

  it("ignores malformed snapshots when aggregating", async () => {
    const { env, kv } = await envWithRules(undefined, {
      overrides: { STATS_TOKEN: "secret" }
    });
    await kv.put("stats:2020-01-01:broken", "not-json{");
    const response = await handleStatsRequest(
      new Request("https://worker.example/stats?token=secret"),
      env
    );
    const body = (await response.json()) as { total: number; blocked: number };
    expect(body.total).toBe(0);
    expect(body.blocked).toBe(0);
  });
});

describe("MemoryKv", () => {
  it("lists keys with prefix filter", async () => {
    const kv = new MemoryKv();
    await kv.put("stats:a", "1");
    await kv.put("rules:b", "2");
    const page = await kv.list({ prefix: "stats:" });
    expect(page.keys.map((key) => key.name)).toEqual(["stats:a"]);
    expect(page.list_complete).toBe(true);
  });
});
