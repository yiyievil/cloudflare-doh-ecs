// 真实数据端到端验证：下载 anti-AD 全量列表，走真实的 update → load → classify 管线。
// 默认跳过，需要网络时运行：RUN_NET_TESTS=1 npx vitest run test/adlist.real.test.ts
declare const process: { env: Record<string, string | undefined> };

import { classifyDomain, ensureAdLists, resetAdListCacheForTest } from "../src/adlist";
import { envWithRules } from "./helpers";

const enabled = process.env.RUN_NET_TESTS === "1";

describe.skipIf(!enabled)("adlist against real anti-AD data", () => {
  beforeEach(() => {
    resetAdListCacheForTest();
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
  });

  it("blocks known ad/tracker domains and passes legit ones", { timeout: 120_000 }, async () => {
    // anti-AD 出于防误伤会豁免少数域名（tanx/alimama/is.snssdk 等），
    // 用 ADBLOCK_EXTRA_BLOCKLIST 并入后应全部命中
    const { env } = await envWithRules(undefined, {
      adlist: null,
      overrides: {
        ADBLOCK_EXTRA_BLOCKLIST: "connect.facebook.net,tanx.com,alimama.com,is.snssdk.com"
      }
    });
    const lists = await ensureAdLists(env);
    expect(lists?.block).not.toBeNull();

    const mustBlock = [
      // 国外
      "doubleclick.net", "googleads.g.doubleclick.net", "googlesyndication.com",
      "google-analytics.com", "adservice.google.com", "googletagmanager.com",
      "connect.facebook.net", "scorecardresearch.com", "hotjar.com",
      "criteo.com", "taboola.com", "outbrain.com", "adnxs.com", "pubmatic.com",
      "amazon-adsystem.com", "moatads.com", "appsflyer.com",
      // 国内广告/追踪
      "hm.baidu.com", "pos.baidu.com", "cpro.baidu.com", "cnzz.com", "umeng.com",
      "gdt.qq.com", "tanx.com", "atanx.alicdn.com", "mediav.com", "miaozhen.com",
      "alimama.com", "wrating.com", "is.snssdk.com", "pglstatp-toutiao.com"
    ];
    const mustPass = [
      "baidu.com", "www.baidu.com", "qq.com", "taobao.com", "github.com",
      "apple.com", "microsoft.com", "bilibili.com", "www.bilibili.com",
      "api.weixin.qq.com", "mp.weixin.qq.com", "fonts.googleapis.com",
      "cdn.jsdelivr.net", "npmjs.com", "registry.npmmirror.com", "example.com"
    ];
    const missed: string[] = [];
    for (const domain of mustBlock) {
      if (classifyDomain(lists!, domain) !== "block") missed.push(domain);
    }
    const falsePositives: string[] = [];
    for (const domain of mustPass) {
      if (classifyDomain(lists!, domain) === "block") falsePositives.push(domain);
    }
    console.log(`missed: ${JSON.stringify(missed)}`);
    console.log(`false positives: ${JSON.stringify(falsePositives)}`);
    // anti-AD 对主流国内外广告域名应近乎全命中；白名单机制可兜底个别误杀
    expect(missed.length).toBeLessThanOrEqual(2);
    expect(falsePositives).toEqual([]);
  });
});
