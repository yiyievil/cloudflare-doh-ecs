import { concatBytes, readU16, toArrayBuffer, writeU16, writeU32 } from "../src/binary";
import { parseDnsMessage } from "../src/dns";
import { handleRequest, resetAdListCacheForTest, resetDnsCacheForTest, resetStatsForTest } from "../src/index";
import { flushStats } from "../src/stats";
import { resetRuleCacheForTest } from "../src/rules";
import { encodeName, envWithRules, makeQuery, makeResponseFromQuery, MemoryKv } from "./helpers";

function base64Url(data: Uint8Array): string {
  let binary = "";
  for (const byte of data) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

interface CraftRecord {
  type: number;
  ttl?: number;
  rdata: Uint8Array;
}

// 构造带 answer 区的上游应答（A/CNAME 等），用于 CNAME 链与 TTL 测试
function craftUpstreamResponse(query: Uint8Array, records: CraftRecord[]): Uint8Array {
  const parsed = parseDnsMessage(query);
  const header = query.slice(0, 12);
  header[2] = (header[2] ?? 0) | 0x80;
  header[3] = (header[3] ?? 0) | 0x80;
  writeU16(header, 6, records.length);
  const parts: Uint8Array[] = [header, query.slice(12, parsed.question.endOffset)];
  for (const record of records) {
    const answer = new Uint8Array(12 + record.rdata.length);
    writeU16(answer, 0, 0xc00c);
    writeU16(answer, 2, record.type);
    writeU16(answer, 4, 1);
    writeU32(answer, 6, record.ttl ?? 60);
    writeU16(answer, 10, record.rdata.length);
    answer.set(record.rdata, 12);
    parts.push(answer);
  }
  return concatBytes(parts);
}

describe("DoH worker", () => {
  beforeEach(() => {
    resetRuleCacheForTest();
    resetAdListCacheForTest();
    resetDnsCacheForTest();
    resetStatsForTest();
    vi.restoreAllMocks();
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
  });

  it("routes domestic POST to AliDNS and injects ECS", async () => {
    const { env } = await envWithRules();
    let destination = "";
    let forwarded = new Uint8Array();
    let redirect: RequestRedirect | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        destination = String(input);
        forwarded = new Uint8Array(init?.body as ArrayBuffer);
        redirect = init?.redirect;
        return new Response(toArrayBuffer(makeResponseFromQuery(forwarded)), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const query = makeQuery("www.qq.com", 1);
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: {
          "content-type": "application/dns-message",
          "x-forwarded-for": "198.51.100.1, 8.8.4.123"
        },
        body: toArrayBuffer(query)
      }),
      env
    );
    expect(response.status).toBe(200);
    expect(destination).toBe("https://dns.alidns.com/dns-query");
    expect(redirect).toBe("manual");
    expect(parseDnsMessage(forwarded).opt).not.toBeNull();
    // 无 answer 记录时按默认 TTL 缓存
    expect(response.headers.get("cache-control")).toBe("public, max-age=60");
  });

  it("routes foreign GET to Google and supports base64url", async () => {
    const { env } = await envWithRules();
    const destinations: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        destinations.push(String(input));
        const body = new Uint8Array(init?.body as ArrayBuffer);
        return new Response(toArrayBuffer(makeResponseFromQuery(body)), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const query = makeQuery("example.net", 65);
    const response = await handleRequest(
      new Request(`https://worker.example/doh?dns=${base64Url(query)}`, {
        headers: { "x-forwarded-for": "2001:4860:4860::8888" }
      }),
      env
    );
    expect(response.status).toBe(200);
    expect(destinations).toEqual(["https://dns.google/dns-query"]);
  });

  it("falls back to CF-Connecting-IP when XFF has no public address", async () => {
    const { env } = await envWithRules();
    let forwarded = new Uint8Array();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
        forwarded = new Uint8Array(init?.body as ArrayBuffer);
        return new Response(toArrayBuffer(makeResponseFromQuery(forwarded)), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const query = makeQuery("example.net", 66);
    const response = await handleRequest(
      new Request(`https://worker.example/doh?dns=${base64Url(query)}`, {
        headers: {
          "x-forwarded-for": "10.0.0.1, 192.168.1.1",
          "cf-connecting-ip": "8.8.4.123"
        }
      }),
      env
    );
    const opt = parseDnsMessage(forwarded).opt;
    const start = opt?.rdataStart ?? 0;
    expect(response.status).toBe(200);
    expect(Array.from(forwarded.slice(start, start + 11))).toEqual([
      0, 8, 0, 7, 0, 1, 24, 0, 8, 8, 4
    ]);
  });

  it("returns DNS SERVFAIL after exhausting the domestic group", async () => {
    const { env } = await envWithRules();
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request) => {
        calls.push(String(input));
        throw new TypeError("request to https://private.example/secret failed");
      })
    );
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("qq.com"))
      }),
      env
    );
    const body = new Uint8Array(await response.arrayBuffer());
    expect(readU16(body, 2) & 0x000f).toBe(2);
    expect(calls).toEqual([
      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"
    ]);
    expect(console.warn).toHaveBeenNthCalledWith(1, "doh_upstream_failed", {
      group: "domestic",
      role: "primary",
      reason: "network_error",
      detail: "TypeError: request to [url] failed"
    });
  });

  it("falls back from Google to Cloudflare without crossing groups", async () => {
    const { env } = await envWithRules();
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        calls.push(String(input));
        if (calls.length === 1) return new Response(null, { status: 503 });
        const body = new Uint8Array(init?.body as ArrayBuffer);
        return new Response(toArrayBuffer(makeResponseFromQuery(body)), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("example.net"))
      }),
      env
    );
    expect(calls).toEqual([
      "https://dns.google/dns-query",
      "https://cloudflare-dns.com/dns-query"
    ]);
    expect(console.warn).toHaveBeenCalledWith("doh_upstream_failed", {
      group: "global",
      role: "primary",
      reason: "http_status_503"
    });
    expect(readU16(new Uint8Array(await response.arrayBuffer()), 2) & 0xf).toBe(0);
  });

  it("falls back from AliDNS when it returns DNS SERVFAIL", async () => {
    const { env } = await envWithRules();
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        calls.push(String(input));
        const body = new Uint8Array(init?.body as ArrayBuffer);
        const dnsBody = makeResponseFromQuery(body);
        if (calls.length === 1) dnsBody[3] = ((dnsBody[3] ?? 0) & 0xf0) | 2;
        return new Response(toArrayBuffer(dnsBody), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("qq.com"))
      }),
      env
    );
    expect(calls).toEqual([
      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"
    ]);
    expect(console.warn).toHaveBeenCalledWith("doh_upstream_failed", {
      group: "domestic",
      role: "primary",
      reason: "dns_servfail"
    });
    expect(readU16(new Uint8Array(await response.arrayBuffer()), 2) & 0xf).toBe(0);
  });

  it("returns FORMERR for malformed DNS and empty HTTP errors for bad transport", async () => {
    const { env } = await envWithRules();
    const malformed = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(Uint8Array.of(1, 2, 3))
      }),
      env
    );
    expect(malformed.headers.get("content-type")).toBe("application/dns-message");
    expect(readU16(new Uint8Array(await malformed.arrayBuffer()), 2) & 0xf).toBe(1);

    const badGet = await handleRequest(
      new Request("https://worker.example/doh?dns=***"),
      env
    );
    expect(badGet.status).toBe(400);
    expect(await badGet.text()).toBe("");

    const wrongPath = await handleRequest(new Request("https://worker.example/"), env);
    // 纯 DoH 域名的非 DoH 路径返回提示文案
    expect(wrongPath.status).toBe(200);
    expect(await wrongPath.text()).toContain("DNS-over-HTTPS endpoint");

    const wrongType = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}"
      }),
      env
    );
    expect(wrongType.status).toBe(415);
  });

  it("rejects invalid upstream response identity", async () => {
    const { env } = await envWithRules();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
        const body = makeResponseFromQuery(new Uint8Array(init?.body as ArrayBuffer));
        body[0] = 0;
        body[1] = 1;
        return new Response(toArrayBuffer(body), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("example.net"))
      }),
      env
    );
    const body = new Uint8Array(await response.arrayBuffer());
    expect(readU16(body, 2) & 0xf).toBe(2);
  });

  it("returns SERVFAIL without leaking invalid environment configuration", async () => {
    const env = {
      RULES_KV: new MemoryKv().asBinding(),
      GLOBAL_DOH_URL: "http://127.0.0.1/dns-query"
    };
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("example.net"))
      }),
      env
    );
    expect(response.status).toBe(200);
    expect(readU16(new Uint8Array(await response.arrayBuffer()), 2) & 0xf).toBe(2);
  });
});

describe("ad blocking", () => {
  beforeEach(() => {
    resetRuleCacheForTest();
    resetAdListCacheForTest();
    resetDnsCacheForTest();
    resetStatsForTest();
    vi.restoreAllMocks();
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
  });

  function stubUpstream() {
    return vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
      const body = new Uint8Array(init?.body as ArrayBuffer);
      return new Response(toArrayBuffer(makeResponseFromQuery(body)), {
        headers: { "content-type": "application/dns-message" }
      });
    });
  }

  it("answers NXDOMAIN for blocklisted domains without contacting upstreams", async () => {
    const { env } = await envWithRules();
    const fetchMock = stubUpstream();
    vi.stubGlobal("fetch", fetchMock);
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("ads.g.doubleclick.net", 1))
      }),
      env
    );
    expect(fetchMock).not.toHaveBeenCalled();
    const body = new Uint8Array(await response.arrayBuffer());
    expect(readU16(body, 2) & 0xf).toBe(3); // NXDOMAIN
    expect(parseDnsMessage(body).question.name.ruleName).toBe("ads.g.doubleclick.net");
    expect(response.headers.get("cache-control")).toBe("public, max-age=30");
  });

  it("forwards queries for allowlisted domains even when blacklisted", async () => {
    const { env } = await envWithRules(undefined, {
      overrides: { ADBLOCK_ALLOWLIST: "doubleclick.net" }
    });
    const fetchMock = stubUpstream();
    vi.stubGlobal("fetch", fetchMock);
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("doubleclick.net", 1))
      }),
      env
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(readU16(new Uint8Array(await response.arrayBuffer()), 2) & 0xf).toBe(0);
  });

  it("stops blocking entirely when ADBLOCK_ENABLED=false", async () => {
    const { env } = await envWithRules(undefined, {
      overrides: { ADBLOCK_ENABLED: "false" }
    });
    const fetchMock = stubUpstream();
    vi.stubGlobal("fetch", fetchMock);
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("doubleclick.net", 1))
      }),
      env
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(readU16(new Uint8Array(await response.arrayBuffer()), 2) & 0xf).toBe(0);
  });

  it("answers 0.0.0.0/:: in zeroip mode and NOERROR-empty for other types", async () => {
    const { env } = await envWithRules(undefined, {
      overrides: { ADBLOCK_RESPONSE: "zeroip" }
    });
    const aResponse = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("doubleclick.net", 1))
      }),
      env
    );
    const aBody = new Uint8Array(await aResponse.arrayBuffer());
    expect(readU16(aBody, 2) & 0x0400).toBe(0x0400); // AA
    expect(readU16(aBody, 6)).toBe(1);
    expect(Array.from(aBody.slice(aBody.length - 4))).toEqual([0, 0, 0, 0]);

    const aaaaResponse = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("doubleclick.net", 28))
      }),
      env
    );
    const aaaaBody = new Uint8Array(await aaaaResponse.arrayBuffer());
    expect(readU16(aaaaBody, 6)).toBe(1);
    expect(Array.from(aaaaBody.slice(aaaaBody.length - 16))).toEqual(new Array<number>(16).fill(0));

    const txtResponse = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("doubleclick.net", 16))
      }),
      env
    );
    const txtBody = new Uint8Array(await txtResponse.arrayBuffer());
    expect(readU16(txtBody, 2) & 0xf).toBe(0);
    expect(readU16(txtBody, 6)).toBe(0);
  });

  it("answers NOERROR-empty in empty mode", async () => {
    const { env } = await envWithRules(undefined, {
      overrides: { ADBLOCK_RESPONSE: "empty" }
    });
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("doubleclick.net", 1))
      }),
      env
    );
    const body = new Uint8Array(await response.arrayBuffer());
    expect(readU16(body, 2) & 0xf).toBe(0);
    expect(readU16(body, 6)).toBe(0);
  });

  it("blocks CNAME-cloaked targets", async () => {
    const { env } = await envWithRules();
    // answer: CNAME → doubleclick.net（黑名单命中）
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        const query = makeQuery("media.brand.example", 1);
        const response = craftUpstreamResponse(query, [
          { type: 5, rdata: encodeName("doubleclick.net") }
        ]);
        return new Response(toArrayBuffer(response), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const blocked = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("media.brand.example", 1))
      }),
      env
    );
    expect(readU16(new Uint8Array(await blocked.arrayBuffer()), 2) & 0xf).toBe(3);
  });

  it("honors allowlisted CNAME chains", async () => {
    // answer: CNAME → hm.baidu.com（白名单豁免）
    const { env } = await envWithRules(undefined, {
      overrides: { ADBLOCK_ALLOWLIST: "hm.baidu.com" }
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        const query = makeQuery("media.brand.example", 1);
        const response = craftUpstreamResponse(query, [
          { type: 5, rdata: encodeName("hm.baidu.com") }
        ]);
        return new Response(toArrayBuffer(response), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const allowed = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("media.brand.example", 1))
      }),
      env
    );
    expect(readU16(new Uint8Array(await allowed.arrayBuffer()), 2) & 0xf).toBe(0);
  });

  it("does not conflate long domains sharing a truncated prefix", async () => {
    const { env } = await envWithRules();
    // 两个域名前 20+ 字节完全一致（旧 30 字节截断键会碰撞）
    const first = makeQuery("aaaaaaaaaaaaaaaaaaaaaa1.example.net", 1);
    const second = makeQuery("aaaaaaaaaaaaaaaaaaaaaa2.example.net", 1);
    const responses = new Map<string, Uint8Array>();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
        const query = new Uint8Array(init?.body as ArrayBuffer);
        const parsed = parseDnsMessage(query);
        const name = parsed.question.name.ruleName ?? "";
        const digit = Number(/a+(\d)\.example/.exec(name)?.[1] ?? 0);
        const response = craftUpstreamResponse(query, [
          { type: 1, rdata: Uint8Array.of(10, 0, 0, digit) }
        ]);
        responses.set(name, response);
        return new Response(toArrayBuffer(response), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const firstResponse = new Uint8Array(
      await (
        await handleRequest(
          new Request("https://worker.example/doh", {
            method: "POST",
            headers: { "content-type": "application/dns-message" },
            body: toArrayBuffer(first)
          }),
          env
        )
      ).arrayBuffer()
    );
    const secondResponse = new Uint8Array(
      await (
        await handleRequest(
          new Request("https://worker.example/doh", {
            method: "POST",
            headers: { "content-type": "application/dns-message" },
            body: toArrayBuffer(second)
          }),
          env
        )
      ).arrayBuffer()
    );
    // 第二个查询不得命中第一个的缓存（旧实现会返回 10.0.0.1）
    expect(secondResponse.slice(-4)).toEqual(Uint8Array.of(10, 0, 0, 2));
    expect(firstResponse.slice(-4)).toEqual(Uint8Array.of(10, 0, 0, 1));
    expect(responses.size).toBe(2);
  });

  it("clamps cache TTL to the upstream answer TTL", async () => {
    const { env } = await envWithRules();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
        const query = new Uint8Array(init?.body as ArrayBuffer);
        const response = craftUpstreamResponse(query, [
          { type: 1, ttl: 100000, rdata: Uint8Array.of(1, 2, 3, 4) }
        ]);
        return new Response(toArrayBuffer(response), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("cache-ttl-up.example.net", 1))
      }),
      env
    );
    expect(response.headers.get("cache-control")).toBe("public, max-age=1800");
  });

  it("exposes aggregated stats behind the token gate", async () => {
    const { env } = await envWithRules(undefined, {
      overrides: { STATS_TOKEN: "secret" }
    });
    await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("doubleclick.net", 1))
      }),
      env
    );
    await flushStats(env); // 测试环境没有 ctx，显式落盘
    const noToken = await handleRequest(
      new Request("https://worker.example/stats"),
      env
    );
    expect(noToken.status).toBe(404);

    const stats = await handleRequest(
      new Request("https://worker.example/stats?token=secret"),
      env
    );
    expect(stats.status).toBe(200);
    const body = (await stats.json()) as { total: number; blocked: number };
    expect(body.total).toBeGreaterThanOrEqual(1);
    expect(body.blocked).toBeGreaterThanOrEqual(1);
  });
});

describe("performance: SWR cache and hedged upstreams", () => {
  beforeEach(() => {
    resetRuleCacheForTest();
    resetAdListCacheForTest();
    resetDnsCacheForTest();
    resetStatsForTest();
    vi.restoreAllMocks();
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
  });

  function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function postQuery(env: Parameters<typeof handleRequest>[1], ctx?: unknown): Promise<Response> {
    return handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("swr.example.net", 1))
      }),
      env,
      ctx as never
    );
  }

  it("serves stale answers immediately and refreshes in the background", async () => {
    vi.useFakeTimers();
    try {
      const { env } = await envWithRules();
      let call = 0;
      vi.stubGlobal(
        "fetch",
        vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
          call += 1;
          const query = new Uint8Array(init?.body as ArrayBuffer);
          const response = craftUpstreamResponse(query, [
            { type: 1, ttl: 60, rdata: Uint8Array.of(call, 0, 0, call) }
          ]);
          return new Response(toArrayBuffer(response), {
            headers: { "content-type": "application/dns-message" }
          });
        })
      );
      const ctxPromises: Promise<unknown>[] = [];
      const ctx = { waitUntil: (p: Promise<unknown>) => ctxPromises.push(p) };

      const first = await postQuery(env, ctx);
      expect(call).toBe(1);
      expect(new Uint8Array(await first.arrayBuffer()).slice(-4)).toEqual(
        Uint8Array.of(1, 0, 0, 1)
      );

      // 61 秒后条目过期，但仍在 30 分钟 stale 窗口内：立即返回旧值
      vi.setSystemTime(Date.now() + 61_000);
      const second = await postQuery(env, ctx);
      expect(call).toBe(1); // 未打上游
      expect(second.headers.get("cache-control")).toBe("no-store");
      expect(new Uint8Array(await second.arrayBuffer()).slice(-4)).toEqual(
        Uint8Array.of(1, 0, 0, 1)
      );

      // 后台刷新完成后，缓存里是新值
      await Promise.all(ctxPromises);
      expect(call).toBe(2);
      const third = await postQuery(env, ctx);
      expect(call).toBe(2);
      expect(new Uint8Array(await third.arrayBuffer()).slice(-4)).toEqual(
        Uint8Array.of(2, 0, 0, 2)
      );
    } finally {
      vi.useRealTimers();
    }
  });

  it("hedges to the fallback when the primary is slow", async () => {
    const { env } = await envWithRules();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        const query = new Uint8Array(init?.body as ArrayBuffer);
        if (String(input).includes("dns.google")) {
          await sleep(600); // 超过 250ms 对冲窗口
          return new Response(
            toArrayBuffer(craftUpstreamResponse(query, [
              { type: 1, ttl: 60, rdata: Uint8Array.of(1, 1, 1, 1) }
            ])),
            { headers: { "content-type": "application/dns-message" } }
          );
        }
        return new Response(
          toArrayBuffer(craftUpstreamResponse(query, [
            { type: 1, ttl: 60, rdata: Uint8Array.of(2, 2, 2, 2) }
          ])),
          { headers: { "content-type": "application/dns-message" } }
        );
      })
    );
    const startedAt = Date.now();
    const response = await postQuery(env);
    const elapsed = Date.now() - startedAt;
    expect(elapsed).toBeLessThan(500);
    expect(new Uint8Array(await response.arrayBuffer()).slice(-4)).toEqual(
      Uint8Array.of(2, 2, 2, 2)
    );
  });

  it("keeps the primary answer when it arrives within the hedge window", async () => {
    const { env } = await envWithRules();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        const query = new Uint8Array(init?.body as ArrayBuffer);
        if (String(input).includes("dns.google")) {
          return new Response(
            toArrayBuffer(craftUpstreamResponse(query, [
              { type: 1, ttl: 60, rdata: Uint8Array.of(1, 1, 1, 1) }
            ])),
            { headers: { "content-type": "application/dns-message" } }
          );
        }
        await sleep(600);
        return new Response(
          toArrayBuffer(craftUpstreamResponse(query, [
            { type: 1, ttl: 60, rdata: Uint8Array.of(2, 2, 2, 2) }
          ])),
          { headers: { "content-type": "application/dns-message" } }
        );
      })
    );
    const startedAt = Date.now();
    const response = await postQuery(env);
    const elapsed = Date.now() - startedAt;
    expect(elapsed).toBeLessThan(500);
    expect(new Uint8Array(await response.arrayBuffer()).slice(-4)).toEqual(
      Uint8Array.of(1, 1, 1, 1)
    );
  });

  it("tracks upstream latency and cache hit rate in stats", async () => {
    const { env } = await envWithRules(undefined, {
      overrides: { STATS_TOKEN: "secret" }
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
        const query = new Uint8Array(init?.body as ArrayBuffer);
        return new Response(
          toArrayBuffer(craftUpstreamResponse(query, [
            { type: 1, ttl: 120, rdata: Uint8Array.of(9, 9, 9, 9) }
          ])),
          { headers: { "content-type": "application/dns-message" } }
        );
      })
    );
    await postQuery(env);
    await postQuery(env); // 命中缓存
    await flushStats(env);

    const stats = await handleRequest(
      new Request("https://worker.example/stats?token=secret"),
      env
    );
    const body = (await stats.json()) as {
      total: number;
      cacheHits: number;
      cacheHitRate: number;
      upstreamCount: number;
      upstreamAvgMs: number;
    };
    expect(body.total).toBe(2);
    expect(body.cacheHits).toBe(1);
    expect(body.cacheHitRate).toBe(50);
    expect(body.upstreamCount).toBe(1);
    expect(body.upstreamAvgMs).toBeGreaterThanOrEqual(0);
  });
});
