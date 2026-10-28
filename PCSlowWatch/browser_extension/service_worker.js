const ENABLED_KEY = "pcslowwatch_enabled";
const SAMPLES_KEY = "pcslowwatch_samples";
const MAX_SAMPLES = 20000;
const RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
let writeQueue = Promise.resolve();

chrome.runtime.onInstalled.addListener(async () => {
  const state = await chrome.storage.local.get([ENABLED_KEY, SAMPLES_KEY]);
  const changes = {};
  if (typeof state[ENABLED_KEY] !== "boolean") changes[ENABLED_KEY] = true;
  if (!Array.isArray(state[SAMPLES_KEY])) changes[SAMPLES_KEY] = [];
  if (Object.keys(changes).length) await chrome.storage.local.set(changes);
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || message.type !== "pcslowwatch_sample" || !message.sample) return false;
  writeQueue = writeQueue.then(() => storeSample(message.sample));
  writeQueue.then(() => sendResponse({ ok: true })).catch(() => sendResponse({ ok: false }));
  return true;
});

async function storeSample(input) {
  const state = await chrome.storage.local.get([ENABLED_KEY, SAMPLES_KEY]);
  if (state[ENABLED_KEY] === false) return;
  const existing = Array.isArray(state[SAMPLES_KEY]) ? state[SAMPLES_KEY] : [];
  const category = cleanCategory(input.site_category);
  const sample = {
    sample_id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    tab_ref: cleanToken(input.tab_ref, 64),
    site_label: cleanSite(input.site_label),
    site_category: category,
    mail_thread_id: category === "email" && input.site_label === "gmail" ? cleanThread(input.mail_thread_id) : "",
    visible: input.visible === true,
    resource_count: safeNumber(input.resource_count, 0, 100000, true),
    transfer_kb: safeNumber(input.transfer_kb, 0, 10000000, false),
    long_task_count: safeNumber(input.long_task_count, 0, 100000, true),
    long_task_ms: safeNumber(input.long_task_ms, 0, 86400000, false),
    js_heap_mb: safeNumber(input.js_heap_mb, 0, 100000, false),
    dom_nodes: safeNumber(input.dom_nodes, 0, 10000000, true),
    load_ms: safeNumber(input.load_ms, 0, 86400000, false)
  };
  if (!sample.site_label) return;
  const cutoff = Date.now() - RETENTION_MS;
  const kept = existing.filter(row => row && Date.parse(row.timestamp) >= cutoff);
  kept.push(sample);
  if (kept.length > MAX_SAMPLES) kept.splice(0, kept.length - MAX_SAMPLES);
  await chrome.storage.local.set({ [SAMPLES_KEY]: kept });
}
function safeNumber(value, min, max, integer) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < min || n > max) return 0;
  return integer ? Math.round(n) : Math.round(n * 100) / 100;
}
function cleanToken(value, max) {
  if (typeof value !== "string") return "";
  const v = value.slice(0, max);
  return /^[A-Fa-f0-9-]{8,64}$/.test(v) ? v : "";
}
function cleanSite(value) {
  if (typeof value !== "string") return "";
  const v = value.toLowerCase().slice(0, 100);
  return /^[a-z0-9.-]{1,100}$/.test(v) ? v : "";
}
function cleanThread(value) {
  if (typeof value !== "string") return "";
  const v = value.slice(0, 100);
  return /^[A-Za-z0-9_-]{8,100}$/.test(v) ? v : "";
}
function cleanCategory(value) {
  const allowed = new Set(["banking", "email", "shopping", "video", "social", "news", "development", "search", "other"]);
  return allowed.has(value) ? value : "other";
}
