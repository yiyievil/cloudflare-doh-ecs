import {
  classifyDomain,
  DEFAULT_ADBLOCK_LIST_URL,
  ensureAdLists,
  getAdLists,
  inspectAdData,
  normalizeDomainList,
  resetAdListCacheForTest,
  updateAdList,
  ADLIST_ALLOWLIST_KEY
} from "../src/adlist";
import { envWithRules } from "./helpers";

function textFetcher(body: string): typeof fetch {
  return vi.fn(async () => {
    return new Response(body, { headers: { "content-type": "text/plain" } });
  }) as unknown as typeof fetch;
}

describe("adlist normalization", () => {
  it("strips comments, case, duplicates, BOM and CRLF, then sorts", () => {
    const text =
      "\uFEFF#TITLE=anti-AD\r\nDoubleClick.NET\r\nads.foo.com\r\n#comment\r\n" +
      "doubleclick.net\r\n!filter\r\nNot A Domain\r\nbar.cn\r\n\r\n";
    expect(normalizeDomainList(text)).toEqual(["ads.foo.com", "bar.cn", "doubleclick.net"]);
  });

  it("keeps single-label and underscore domains", () => {
    expect(normalizeDomainList("localhost\n_dmarc.foo.com\nxn--fiq228c.com")).toEqual([
      "_dmarc.foo.com",
      "localhost",
      "xn--fiq228c.com"
    ]);
  });

  it("validates stored form strictly", () => {
    const bytes = (text: string) => new TextEncoder().encode(text);
    expect(inspectAdData(bytes("a.cn\nb.cn"))).toBe(2);
    expect(() => inspectAdData(bytes("b.cn\na.cn"))).toThrow("adlist_not_strictly_sorted");
    expect(() => inspectAdData(bytes("a.cn\nB.cn"))).toThrow("adlist_invalid_char");
    expect(() => inspectAdData(bytes("a.cn\r\nb.cn"))).toThrow("adlist_invalid_char");
    expect(() => inspectAdData(bytes("a.cn\n\nb.cn"))).toThrow("adlist_empty_line");
    expect(() => inspectAdData(new Uint8Array(0))).toThrow("adlist_size_invalid");
    expect(() => inspectAdData(bytes("dup.cn\ndup.cn"))).toThrow("adlist_not_strictly_sorted");
  });
});

describe("adlist classification", () => {
  beforeEach(() => {
    resetAdListCacheForTest();
  });

  it("blocks exact and subdomains, leaves unrelated domains alone", async () => {
    const { env } = await envWithRules();
    const lists = await ensureAdLists(env);
    expect(lists?.block).not.toBeNull();
    expect(classifyDomain(lists!, "doubleclick.net")).toBe("block");
    expect(classifyDomain(lists!, "ads.g.doubleclick.net")).toBe("block");
    expect(classifyDomain(lists!, "sub.hm.baidu.com")).toBe("block");
    // 后缀匹配必须按域边界，不能把 evil-hm.baidu.com 之类误伤
    expect(classifyDomain(lists!, "evildoubleclick.net")).toBe("none");
    expect(classifyDomain(lists!, "hm.baidu.com.evil.example")).toBe("none");
    expect(classifyDomain(lists!, "baidu.com")).toBe("none");
    expect(classifyDomain(lists!, "qq.com")).toBe("none");
  });

  it("allows allowlisted domains even when also blacklisted", async () => {
    const { env } = await envWithRules(undefined, {
      overrides: { ADBLOCK_ALLOWLIST: "cnzz.com safe.example" }
    });
    const lists = await ensureAdLists(env);
    expect(lists?.allow.has("cnzz.com")).toBe(true);
    expect(classifyDomain(lists!, "cnzz.com")).toBe("allow");
    expect(classifyDomain(lists!, "s.cnzz.com")).toBe("allow");
    expect(classifyDomain(lists!, "doubleclick.net")).toBe("block");
  });

  it("merges allowlist from KV text key", async () => {
    const { env, kv } = await envWithRules();
    await kv.put(ADLIST_ALLOWLIST_KEY, "doubleclick.net");
    const lists = await ensureAdLists(env);
    expect(lists?.allow.has("doubleclick.net")).toBe(true);
    expect(classifyDomain(lists!, "doubleclick.net")).toBe("allow");
  });
});

describe("adlist update pipeline", () => {
  beforeEach(() => {
    resetAdListCacheForTest();
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
  });

  it("downloads, normalizes, sorts and atomically switches versions", async () => {
    const { env, kv } = await envWithRules(undefined, { adlist: null });
    const fetcher = textFetcher("#title\ncnzz.com\nZZZ.example\naaa.example\ncnzz.com");
    await expect(updateAdList(env, fetcher)).resolves.toBe("updated");

    const manifest = (await kv.get("adlist:active", "json")) as {
      active: string;
      previous: string | null;
    };
    expect(manifest.active).toMatch(/^adlist:data:/);
    expect(manifest.previous).toBeNull();
    const stored = new TextDecoder().decode(
      new Uint8Array((await kv.get(manifest.active, "arrayBuffer")) as ArrayBuffer)
    );
    expect(stored.split("\n")).toEqual(["aaa.example", "cnzz.com", "zzz.example"]);

    const lists = await getAdLists(env, Date.now(), true);
    expect(classifyDomain(lists!, "sub.zzz.example")).toBe("block");
  });

  it("reports unchanged when content matches the active version", async () => {
    const { env } = await envWithRules(undefined, { adlist: null });
    const fetcher = textFetcher("ads.a\nads.b");
    await expect(updateAdList(env, fetcher)).resolves.toBe("updated");
    await expect(updateAdList(env, fetcher)).resolves.toBe("unchanged");
  });

  it("rejects html responses and empty lists", async () => {
    const { env } = await envWithRules(undefined, { adlist: null });
    const htmlFetcher = vi.fn(async () => {
      return new Response("<html>blocked</html>", { headers: { "content-type": "text/html" } });
    }) as unknown as typeof fetch;
    await expect(updateAdList(env, htmlFetcher)).rejects.toThrow("adlist_download_html");

    const emptyFetcher = textFetcher("# only comments\n");
    await expect(updateAdList(env, emptyFetcher)).rejects.toThrow("adlist_empty");
  });

  it("keeps previous version for rollback and cleans obsolete keys", async () => {
    const { env, kv } = await envWithRules(undefined, { adlist: null });
    await updateAdList(env, textFetcher("ads.a\nads.b\nads.c"));
    const firstManifest = (await kv.get("adlist:active", "json")) as { active: string };
    const firstKey = firstManifest.active;

    await updateAdList(env, textFetcher("ads.d\nads.e"));
    const secondManifest = (await kv.get("adlist:active", "json")) as {
      active: string;
      previous: string | null;
    };
    expect(secondManifest.previous).toBe(firstKey);
    expect(secondManifest.active).not.toBe(firstKey);

    await updateAdList(env, textFetcher("ads.f\nads.g"));
    expect(kv.values.has(firstKey)).toBe(false);
    const thirdManifest = (await kv.get("adlist:active", "json")) as { previous: string | null };
    expect(thirdManifest.previous).toBe(secondManifest.active);
  });

  it("bootstraps on first query and backs off after a failed download", async () => {
    const { env } = await envWithRules(undefined, { adlist: null });
    const failing = vi.fn(async () => {
      throw new TypeError("network unreachable");
    });
    vi.stubGlobal("fetch", failing);
    const lists1 = await ensureAdLists(env);
    expect(lists1?.block ?? null).toBeNull();
    // 退避窗口内紧接着的第二次调用不得重复下载
    const lists2 = await ensureAdLists(env);
    expect(lists2?.block ?? null).toBeNull();
    expect(failing).toHaveBeenCalledTimes(1);

    // 退避状态复位后，恢复下载即可重新引导
    resetAdListCacheForTest();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        return new Response("doubleclick.net", { headers: { "content-type": "text/plain" } });
      })
    );
    const lists3 = await ensureAdLists(env);
    expect(classifyDomain(lists3!, "doubleclick.net")).toBe("block");
  });

  it("merges ADBLOCK_EXTRA_BLOCKLIST into the stored list", async () => {
    const { env } = await envWithRules(undefined, {
      adlist: null,
      overrides: { ADBLOCK_EXTRA_BLOCKLIST: "anti-ad-skipped.example, ads.extra.cn" }
    });
    // 模拟 anti-AD 出于防误伤豁免了 anti-ad-skipped.example
    await updateAdList(env, textFetcher("ads.a\nads.b"));
    const lists = await getAdLists(env, Date.now(), true);
    expect(classifyDomain(lists!, "anti-ad-skipped.example")).toBe("block");
    expect(classifyDomain(lists!, "sub.ads.extra.cn")).toBe("block");
    expect(classifyDomain(lists!, "ads.a")).toBe("block");
  });

  it("uses ADBLOCK_LIST_URL when configured and defaults to anti-AD", async () => {
    expect(DEFAULT_ADBLOCK_LIST_URL).toBe("https://anti-ad.net/domains.txt");
    const { env } = await envWithRules(undefined, {
      adlist: null,
      overrides: { ADBLOCK_LIST_URL: "https://mirror.example/domains.txt" }
    });
    const fetcher = vi.fn(async (input: string | URL | Request) => {
      expect(String(input)).toBe("https://mirror.example/domains.txt");
      return new Response("blocked.example", { headers: { "content-type": "text/plain" } });
    }) as unknown as typeof fetch;
    await updateAdList(env, fetcher);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
});
