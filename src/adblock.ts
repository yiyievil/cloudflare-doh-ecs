// 广告域名黑名单：从 EasyList 常用域名中筛选的高价值广告/追踪域名
// 命中列表（含任意子域名）会将 DNS 查询直接拦截为 NXDOMAIN。

const AD_DOMAINS: readonly string[] = [
  "24illusions.com","aboutads.quantcast.com","ad.doubleclick.net","adbutler.com","adcolony.com","adform.com","adform.net","adgear.com",
  "adikteev.com","adition.com","adjust.com","adkernel.com","adman.gr","admanmedia.com","admob.com","adnami.io",
  "adnium.com","adnxs.com","adotmob.com","adpays.net","adperfect.com","adplugg.com","adpushup.com","adreactor.com",
  "adrecover.com","adrino.io","adroll.com","adscale.de","adserverpub.com","adservice.google.com","adskeeper.com","adspirit.de",
  "adsrvr.org","adsterra.com","adswizz.com","adtech.com","adtech.de","adtechus.com","adtelligent.com","adtng.com",
  "adtrue.com","advertise.com","advertising.com","advertserve.com","advombat.ru","adxchanger.com","adyoulike.com","adzerk.net",
  "affiliatefuture.com","affiliatewindow.com","afftrack.com","aidata.io","aimatch.com","amazon-adsystem.com","amobee.com","amplitude.com",
  "ampxchange.com","aniview.com","applixir.com","appnext.com","appnexus.com","appsflyer.com","atdmt.com","atomex.net",
  "atwola.com","bidder.criteo.com","branch.io","bugsnag.com","bytedance.com","byteoversea.com","casalemedia.com","chartboost.com",
  "clevertap.com","click.alibaba.com","clicky.com","cnzz.com","comscore.com","content.ad","conversantmedia.com","cpro.baidu.com",
  "crazyegg.com","criteo.com","criteo.net","districtm.net","doubleclick.net","exoclick.com","fls.doubleclick.net","flurry.com",
  "fullstory.com","g.doubleclick.net","getui.com","google-analytics.com","googleadservices.com","googlesyndication.com","googletagmanager.com","googletagservices.com",
  "growingio.com","gtimg.cn","gumgum.com","hm.baidu.com","hotjar.com","indexexchange.com","integralads.com","japfg-trending-content.uc.r.appspot.com",
  "jiguang.cn","kochava.com","macro.adnami.io","mgid.com","mixpanel.com","moatads.com","mopub.com","mouseflow.com",
  "newrelic.com","nielsen.com","onscroll.com","openx.net","optimizely.com","outbrain.com","pagead2.googlesyndication.com","paid.outbrain.com",
  "pangle.io","partner.googleadservices.com","partner.video.syndication.msn.com","pips.taboola.com","popads.net","popcash.net","pos.baidu.com","propellerads.com",
  "pstatp.com","pubmatic.com","pulsepoint.com","quantcast.com","retailmedia-static.criteo.com","revcontent.com","rhythmone.com","rubiconproject.com",
  "scorecardresearch.com","segment.com","sensorsdata.cn","sentry.io","sharethrough.com","smartadserver.com","snssdk.com","sonobi.com",
  "sovrn.com","statcounter.com","static.doubleclick.net","taboola.com","talkingdata.com","teads.tv","trafficjunky.com","triplelift.com",
  "umeng.com","undertone.com","union.baidu.com","unityads.unity3d.com","video-ads.a2z.com","vungle.com","web.adblade.com","widgets.outbrain.com",
  "wixlabs-adsense-v3.uc.r.appspot.com","yieldlab.net","yieldmo.com","zedo.com","zemanta.com"
];

const adDomainSet = new Set<string>(AD_DOMAINS);

/**
 * 判断给定域名（含任意层子域名）是否命中广告黑名单。
 * 例如 ad.doubleclick.net 命中 doubleclick.net。
 */
export function isAdDomain(qname: string | null | undefined): boolean {
  if (!qname) return false;
  if (adDomainSet.has(qname)) return true;
  let idx = 0;
  while (idx >= 0) {
    idx = qname.indexOf(".", idx + 1);
    if (idx < 0) break;
    if (adDomainSet.has(qname.slice(idx + 1))) return true;
  }
  return false;
}
