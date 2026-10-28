(() => {
  "use strict";
  if (window.top !== window || window.__pcSlowWatchInjected) return;
  window.__pcSlowWatchInjected = true;
  const SAMPLE_INTERVAL_MS = 15000;
  const tabRef = crypto.randomUUID();
  let longTaskCount = 0, longTaskMs = 0;

  try {
    if ("PerformanceObserver" in window) {
      const observer = new PerformanceObserver(list => {
        for (const entry of list.getEntries()) {
          longTaskCount += 1;
          longTaskMs += Math.max(0, Number(entry.duration) || 0);
        }
      });
      observer.observe({ type: "longtask", buffered: true });
    }
  } catch (_e) {}

  function rootDomain(host) {
    const parts = String(host || "").toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
    if (parts.length <= 2) return parts.join(".");
    const suffixes = new Set(["co.il","org.il","ac.il","gov.il","net.il","k12.il","co.uk","org.uk","ac.uk","gov.uk","com.au","net.au","org.au","co.nz","com.br","com.tr","co.jp","com.sg","co.my"]);
    return suffixes.has(parts.slice(-2).join(".")) ? parts.slice(-3).join(".") : parts.slice(-2).join(".");
  }
  function siteLabel(host) {
    const h = String(host || "").toLowerCase();
    if (h === "mail.google.com" || h === "gmail.com" || h.endsWith(".gmail.com")) return "gmail";
    if (h.includes("outlook")) return "outlook";
    if (h === "mail.yahoo.com" || h.endsWith(".yahoo.com")) return "yahoo-mail";
    return rootDomain(h);
  }
  function categoryFor(host) {
    const h = String(host || "").toLowerCase(), domain = rootDomain(h);
    const banks = new Set(["leumi.co.il","bankhapoalim.co.il","discountbank.co.il","mizrahi-tefahot.co.il","fibi.co.il","mercantile.co.il","bankotsar.co.il","beinleumi.co.il","onezerobank.com","pepper.co.il","massad.co.il"]);
    if (banks.has(domain) || /(^|[.-])bank([.-]|$)/.test(h) || /banking/.test(h)) return "banking";
    if (h === "mail.google.com" || h === "gmail.com" || h.endsWith(".gmail.com") || h.includes("outlook") || h.includes("yahoo.com")) return "email";
    if (/(youtube|netflix|twitch|vimeo|spotify)/.test(domain)) return "video";
    if (/(facebook|instagram|tiktok|x.com|twitter|reddit|linkedin|threads.net)/.test(domain)) return "social";
    if (/(amazon|ebay|aliexpress|temu|shufersal|wolt|ksp.co.il|ivory.co.il)/.test(domain)) return "shopping";
    if (/(news|ynet|mako|walla|haaretz|globes|calcalist|themarker)/.test(domain)) return "news";
    if (/(github|gitlab|stackoverflow|developer.mozilla|npmjs)/.test(domain)) return "development";
    if (/(google.com|bing.com|duckduckgo.com|search.brave.com)/.test(domain)) return "search";
    return "other";
  }
  function gmailThreadId(host) {
    if (!(host === "mail.google.com" || host.endsWith(".gmail.com"))) return "";
    const route = String(location.hash || "").replace(/^#/, "").split("?")[0];
    const parts = route.split("/").filter(Boolean);
    const folders = new Set(["inbox","all","sent","starred","important","drafts","spam","trash","snoozed","scheduled","category"]);
    let candidate = "";
    if (parts.length >= 2 && folders.has(parts[0].toLowerCase())) candidate = parts[0].toLowerCase() === "category" && parts.length >= 3 ? parts[parts.length - 1] : parts[1];
    else if (parts.length >= 3 && parts[0].toLowerCase() === "label") candidate = parts[parts.length - 1];
    return /^[A-Za-z0-9_-]{12,100}$/.test(candidate) ? candidate : "";
  }
  function samplePage() {
    chrome.storage.local.get(["pcslowwatch_enabled"], state => {
      if (chrome.runtime.lastError || state.pcslowwatch_enabled === false) return;
      try {
        const host = String(location.hostname || "").toLowerCase();
        if (!host || host === "localhost" || host === "127.0.0.1") return;
        const resources = performance.getEntriesByType("resource");
        let transferBytes = 0;
        for (const entry of resources) transferBytes += Math.max(0, Number(entry.transferSize || entry.encodedBodySize || 0));
        const nav = performance.getEntriesByType("navigation")[0], mem = performance.memory;
        const sample = {
          tab_ref: tabRef, site_label: siteLabel(host), site_category: categoryFor(host), mail_thread_id: gmailThreadId(host),
          visible: document.visibilityState === "visible", resource_count: resources.length,
          transfer_kb: Math.round((transferBytes / 1024) * 100) / 100,
          long_task_count: longTaskCount, long_task_ms: Math.round(longTaskMs * 100) / 100,
          js_heap_mb: mem && Number.isFinite(mem.usedJSHeapSize) ? Math.round((mem.usedJSHeapSize / (1024 * 1024)) * 100) / 100 : 0,
          dom_nodes: document.getElementsByTagName("*").length,
          load_ms: nav ? Math.max(0, Number(nav.loadEventEnd || nav.domContentLoadedEventEnd || 0) - Number(nav.startTime || 0)) : 0
        };
        longTaskCount = 0; longTaskMs = 0;
        chrome.runtime.sendMessage({ type: "pcslowwatch_sample", sample }, () => void chrome.runtime.lastError);
      } catch (_e) {}
    });
  }
  samplePage();
  window.setInterval(samplePage, SAMPLE_INTERVAL_MS);
})();
