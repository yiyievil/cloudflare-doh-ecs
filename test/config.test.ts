import { readConfig } from "../src/config";
import { MemoryKv } from "./helpers";

describe("worker configuration", () => {
  const base = () => ({ RULES_KV: new MemoryKv().asBinding() });

  it("uses safe defaults and accepts valid overrides", () => {
    expect(readConfig(base())).toMatchObject({
      path: "/doh",
      domesticUrls: [
        "https://dns.alidns.com/dns-query",
        "https://doh.pub/dns-query"
      ],
      globalUrls: [
        "https://dns.google/dns-query",
        "https://cloudflare-dns.com/dns-query"
      ]
    });
    expect(
      readConfig({
        ...base(),
        DOH_PATH: "/private-doh",
        GLOBAL_DOH_URL: "https://resolver.example/dns-query",
        GLOBAL_FALLBACK_DOH_URL: "https://backup.example/dns-query"
      })
    ).toMatchObject({
      path: "/private-doh",
      globalUrls: [
        "https://resolver.example/dns-query",
        "https://backup.example/dns-query"
      ]
    });
  });

  it.each([
    { DOH_PATH: "dns-query" },
    { DOH_PATH: "//evil" },
    { GLOBAL_DOH_URL: "http://8.8.8.8/dns-query" },
    { GLOBAL_DOH_URL: "https://user:pass@example.com/dns-query" },
    { GLOBAL_DOH_URL: "https://127.0.0.1/dns-query" },
    { GLOBAL_DOH_URL: "https://[::1]/dns-query" },
    { GLOBAL_DOH_URL: "https://example.com/dns-query?target=x" },
    { DOMESTIC_FALLBACK_DOH_URL: "https://127.0.0.1/dns-query" },
    { ADBLOCK_ENABLED: "maybe" },
    { ADBLOCK_RESPONSE: "drop-packets" },
    { ADBLOCK_LIST_URL: "http://anti-ad.net/domains.txt" }
  ])("rejects unsafe config %#", (override) => {
    expect(() => readConfig({ ...base(), ...override })).toThrow();
  });

  it("parses ad blocking options", () => {
    expect(readConfig(base())).toMatchObject({
      adblockEnabled: true,
      adblockListUrl: "https://anti-ad.net/domains.txt",
      adblockResponse: "nxdomain"
    });
    expect(
      readConfig({
        ...base(),
        ADBLOCK_ENABLED: "false",
        ADBLOCK_RESPONSE: "ZEROIP",
        ADBLOCK_LIST_URL: "https://mirror.example/list.txt"
      })
    ).toMatchObject({
      adblockEnabled: false,
      adblockResponse: "zeroip",
      adblockListUrl: "https://mirror.example/list.txt"
    });
  });
});
