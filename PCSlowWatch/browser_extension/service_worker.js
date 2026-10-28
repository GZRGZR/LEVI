const ENABLED_KEY = "pcslowwatch_enabled";
const LEGACY_SAMPLES_KEY = "pcslowwatch_samples";
const SAMPLES_PREFIX = "pcslowwatch_samples_";
const LAST_CLEANUP_KEY = "pcslowwatch_last_cleanup_bucket";
const MAX_SAMPLES = 20000;
const RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
const BUCKET_MS = 5 * 60 * 1000;

let writeQueue = Promise.resolve();
let initialization = null;
let writesSinceCleanup = 0;

chrome.runtime.onInstalled.addListener(() => {
  initialization = null;
  ensureInitialized().catch(() => {});
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || message.type !== "pcslowwatch_sample" || !message.sample) return false;

  const task = writeQueue.catch(() => undefined).then(async () => {
    await ensureInitialized();
    await storeSample(message.sample);
  });
  writeQueue = task;
  task.then(
    () => sendResponse({ ok: true }),
    () => sendResponse({ ok: false })
  );
  return true;
});

function ensureInitialized() {
  if (!initialization) {
    initialization = initializeStorage().catch(error => {
      initialization = null;
      throw error;
    });
  }
  return initialization;
}

async function initializeStorage() {
  const state = await chrome.storage.local.get([ENABLED_KEY, LEGACY_SAMPLES_KEY]);
  if (typeof state[ENABLED_KEY] !== "boolean") {
    await chrome.storage.local.set({ [ENABLED_KEY]: true });
  }

  // Migrate the prior single-array format without duplicating a near-quota store.
  const legacy = state[LEGACY_SAMPLES_KEY];
  if (Array.isArray(legacy)) {
    const legacyRows = legacy.slice(-MAX_SAMPLES);
    const cutoff = Date.now() - RETENTION_MS;
    const groups = {};
    for (const input of legacyRows) {
      const timestamp = Date.parse(input && input.timestamp);
      if (!Number.isFinite(timestamp) || timestamp < cutoff) continue;
      const sample = sanitizeSample(input, timestamp, true);
      if (!sample || !sample.site_label) continue;
      const key = bucketKey(timestamp);
      if (!groups[key]) groups[key] = [];
      groups[key].push(sample);
    }

    // Free the old array before writing its bucketed replacement, otherwise
    // the temporary duplicate could exceed chrome.storage.local's quota.
    await chrome.storage.local.remove(LEGACY_SAMPLES_KEY);
    try {
      if (Object.keys(groups).length) await chrome.storage.local.set(groups);
      await pruneSamples();
    } catch (_error) {
      // Keep the most recent portion if migration cannot fit; the extension can
      // still collect new samples, and a later startup may migrate this smaller set.
      const current = await chrome.storage.local.get(null);
      const partialKeys = Object.keys(groups).filter(key => Array.isArray(current[key]));
      if (partialKeys.length) await chrome.storage.local.remove(partialKeys);
      await chrome.storage.local.set({
        [LEGACY_SAMPLES_KEY]: legacyRows.slice(-5000)
      });
    }
  }
}

async function storeSample(input) {
  const now = Date.now();
  const sample = sanitizeSample(input, now, false);
  if (!sample || !sample.site_label) return;

  const key = bucketKey(now);
  const bucketId = Math.floor(now / BUCKET_MS);
  // Read the current bucket, toggle and cleanup marker in a single storage call.
  const state = await chrome.storage.local.get([ENABLED_KEY, key, LAST_CLEANUP_KEY]);
  if (state[ENABLED_KEY] === false) return;

  const bucket = Array.isArray(state[key]) ? state[key] : [];
  bucket.push(sample);
  await chrome.storage.local.set({ [key]: bucket });

  writesSinceCleanup += 1;
  const lastCleanupBucket = Number.isFinite(state[LAST_CLEANUP_KEY]) ? state[LAST_CLEANUP_KEY] : -1;
  if (writesSinceCleanup >= 200 || bucketId !== lastCleanupBucket) {
    await pruneSamples();
    writesSinceCleanup = 0;
  }
}

function sanitizeSample(input, timestampValue, preserveTimestamp) {
  if (!input || typeof input !== "object") return null;
  const category = cleanCategory(input.site_category);
  const site = cleanSite(input.site_label);
  const parsed = preserveTimestamp ? timestampValue : Date.parse(input.timestamp);
  const timestamp = Number.isFinite(parsed) ? new Date(parsed).toISOString() : new Date(timestampValue).toISOString();
  const id = typeof input.sample_id === "string" && /^[A-Fa-f0-9-]{8,64}$/.test(input.sample_id)
    ? input.sample_id : crypto.randomUUID();

  return {
    sample_id: id,
    timestamp,
    tab_ref: cleanToken(input.tab_ref, 64),
    site_label: site,
    site_category: category,
    mail_thread_id: category === "email" && site === "gmail" ? cleanThread(input.mail_thread_id) : "",
    visible: input.visible === true,
    resource_count: safeNumber(input.resource_count, 0, 100000, true),
    transfer_kb: safeNumber(input.transfer_kb, 0, 10000000, false),
    long_task_count: safeNumber(input.long_task_count, 0, 100000, true),
    long_task_ms: safeNumber(input.long_task_ms, 0, 86400000, false),
    js_heap_mb: safeNumber(input.js_heap_mb, 0, 100000, false),
    dom_nodes: safeNumber(input.dom_nodes, 0, 10000000, true),
    load_ms: safeNumber(input.load_ms, 0, 86400000, false)
  };
}

async function pruneSamples() {
  const state = await chrome.storage.local.get(null);
  const now = Date.now();
  const cutoff = now - RETENTION_MS;
  const entries = Object.entries(state)
    .filter(([key, value]) => key.startsWith(SAMPLES_PREFIX) && Array.isArray(value))
    .map(([key, rows]) => ({
      key,
      rows,
      bucket: Number(key.slice(SAMPLES_PREFIX.length)),
      bucketTime: Number(key.slice(SAMPLES_PREFIX.length)) * BUCKET_MS
    }))
    .sort((a, b) => a.bucket - b.bucket);

  const remove = [];
  const valid = [];
  let total = 0;
  for (const entry of entries) {
    if (!Number.isFinite(entry.bucket) || entry.bucketTime < cutoff) {
      remove.push(entry.key);
      continue;
    }
    valid.push(entry);
    total += entry.rows.length;
  }

  // Remove oldest samples if the cap is exceeded. Normally whole old buckets
  // disappear, but trim a bucket if it alone contains more rows than the excess.
  for (const entry of valid) {
    if (total <= MAX_SAMPLES) break;
    const excess = total - MAX_SAMPLES;
    if (entry.rows.length <= excess) {
      remove.push(entry.key);
      total -= entry.rows.length;
    } else {
      const trimmed = entry.rows.slice(excess);
      await chrome.storage.local.set({ [entry.key]: trimmed });
      total -= excess;
    }
  }
  if (remove.length) await chrome.storage.local.remove(remove);
  await chrome.storage.local.set({
    [LAST_CLEANUP_KEY]: Math.floor(now / BUCKET_MS)
  });
}

function bucketKey(timestamp) {
  return SAMPLES_PREFIX + String(Math.floor(timestamp / BUCKET_MS)).padStart(12, "0");
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
