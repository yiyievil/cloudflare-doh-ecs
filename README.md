# Cloudflare DoH ECS

一个部署在 Cloudflare Workers 上的 DNS-over-HTTPS 服务，支持国内外域名分流、广告拦截、ECS 和上游故障回退。

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Akiiia/cloudflare-doh-ecs)

## 相关链接

- [LINUX DO 社区发布帖](https://linux.do/t/topic/2665830)：项目介绍、部署教程与交流讨论。

## 功能

- 支持 RFC 8484 DoH GET 和 POST 请求
- 国内域名使用 AliDNS，失败后回退腾讯 DNSPod
- 其他域名使用 Google DNS，失败后回退 Cloudflare DNS
- 默认启用 ECS：IPv4 固定使用 `/24`，IPv6 固定使用 `/56`
- 国内域名规则通过 Workers KV 和 Cron Trigger 自动更新
- 广告/追踪域名拦截：每日自动同步 [anti-AD](https://anti-ad.net/) 列表到 KV，
  白名单豁免、CNAME 伪装链检查、可配置拦截响应（NXDOMAIN / 0.0.0.0 / NOERROR 空）
- 查询与拦截效果统计（可选，见 `/stats`）
- 不记录完整查询域名和客户端 IP

## 部署

点击上方 **Deploy to Cloudflare** 按钮，授权 Cloudflare 访问 GitHub。系统会复制项目模板，并在你的 GitHub 账户下创建一个独立的部署仓库。
Cloudflare 会通过该仓库自动创建并部署 Worker、KV 命名空间以及每日规则更新任务。

部署完成后打开详情页-域-启用

DoH 地址：

```text
https://<你的 Worker 域名>/doh
```

首次查询会自动下载并初始化国内域名规则与广告拦截列表（约 2 MB，仅该次查询稍慢）。
每日 Cron 会同时更新国内域名规则和广告拦截列表。

## 广告拦截

- **数据源**：[anti-AD](https://anti-ad.net/domains.txt)（聚合国内外的 DNS 级拦截列表，自带防误伤治理），每日 Cron 更新，KV 中原子切换版本并保留上一版回滚。
- **匹配语义**：查询域名或其任意父后缀命中即拦截；白名单优先于黑名单。
- **CNAME 伪装链**：上游应答中每级 CNAME 指向的域名都会再次核对黑/白名单，专治追踪域名借品牌域名 CNAME 伪装。
- **拦截响应**（`ADBLOCK_RESPONSE`）：
  - `nxdomain`（默认）：返回 NXDOMAIN，行为最干净；
  - `zeroip`：A 查询返回 `0.0.0.0`、AAAA 返回 `::`（其余类型返回 NOERROR 空），对反复重试的 App 广告 SDK 更平顺；
  - `empty`：一律返回 NOERROR 空 answer。
- **自定义**：
  - `ADBLOCK_EXTRA_BLOCKLIST`：追加自选拦截域名（空格/逗号分隔），随每日更新一并入库；
  - `ADBLOCK_ALLOWLIST`：环境变量白名单；也可在 KV 写入 `adlist:allowlist` 键（同样格式），两者合并生效；
  - `ADBLOCK_ENABLED=false` 一键关闭拦截。
- **效果可观测**：设置 `STATS_TOKEN` 后访问 `https://<你的 Worker 域名>/stats?token=<STATS_TOKEN>`，
  返回查询总数、拦截总数与拦截次数 Top 50 域名（按天聚合，仅保留 31 天，不落原始查询日志）。

## 默认上游

| 分组 | 主上游 | 备用上游 |
|---|---|---|
| 国内域名 | AliDNS | 腾讯 DNSPod |
| 其他域名 | Google DNS | Cloudflare DNS |

主上游出现网络错误、超时、异常响应或 DNS `SERVFAIL` 时，才会尝试同组备用上游；不会在国内和国外分组之间回退。

## 配置

所有配置都有默认值，一键部署时无需修改。

| 变量 | 默认值 |
|---|---|
| `DOH_PATH` | `/doh` |
| `DOMESTIC_DOH_URL` | `https://dns.alidns.com/dns-query` |
| `DOMESTIC_FALLBACK_DOH_URL` | `https://doh.pub/dns-query` |
| `GLOBAL_DOH_URL` | `https://dns.google/dns-query` |
| `GLOBAL_FALLBACK_DOH_URL` | `https://cloudflare-dns.com/dns-query` |
| `ADBLOCK_ENABLED` | `true` |
| `ADBLOCK_LIST_URL` | `https://anti-ad.net/domains.txt` |
| `ADBLOCK_EXTRA_BLOCKLIST` | （空） |
| `ADBLOCK_ALLOWLIST` | （空） |
| `ADBLOCK_RESPONSE` | `nxdomain` |
| `STATS_TOKEN` | （空，不开启则 `/stats` 返回 404） |

国内域名规则来自 [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat) 的 `direct-list.txt`，每天自动更新。

## 客户端配置

`config/` 目录提供 Sparkle / FlClash（mihomo 内核）覆写文件：

- `doh-only.yaml`：所有 DNS 走自建 DoH，DNS 层广告净化（配合本 Worker 的拦截能力）；
- `override.yaml`：整体分流，附带 anti-AD 的 Clash 规则集作为客户端侧第二层拦截。

## 注意
- 部分受限网络环境无法访问 .workers.dev 域名，需绑定自有域名或另外使用 CDN 以达到加速访问目的。
- ECS 地址优先取自 `X-Forwarded-For` 中最左侧的合法公网 IP；没有有效地址时回退到 `CF-Connecting-IP`，并自动掩码为 IPv4 `/24` 或 IPv6 `/56`。
- DNS 响应缓存的键覆盖完整 question 与 ECS 子网，缓存时长取上游应答的最小 TTL（限制在 30–300 秒）。
- 广告列表的首次引导与每日更新需一次性处理约 10.8 万条域名（约 130ms CPU）；若触发套餐 CPU 限制导致失败，会自动退避重试，已入库的列表继续生效，不影响正常拦截。查询路径仅做 sha256 完整性校验与二分查找，开销在毫秒级。
- 每个上游超时为 2 秒；主备均超时时，最坏等待约 4 秒。
- DNS 层拦截无法覆盖"广告与正文同域名"的场景（如部分信息流广告），这类需浏览器级（uBlock）或网关级方案补充。
- 本项目不提供公共 DNS 服务的滥用防护，公开部署时建议配合 Cloudflare WAF 或限速规则。

## 本地开发

需要 Node.js 20 或更高版本。

```bash
npm install
npm run typecheck
npm test
npm run deploy:dry-run
```

联网端到端验证（下载真实 anti-AD 列表，默认跳过）：

```bash
RUN_NET_TESTS=1 npx vitest run test/adlist.real.test.ts
```

## 许可证

MIT
