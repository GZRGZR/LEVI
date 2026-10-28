const ENABLED_KEY = "pcslowwatch_enabled";
const LEGACY_SAMPLES_KEY = "pcslowwatch_samples";
const SAMPLES_PREFIX = "pcslowwatch_samples_";
const LAST_CLEANUP_KEY = "pcslowwatch_last_cleanup_bucket";
const MAX_SAMPLES = 20000;
const enabledBox = document.getElementById("enabled"), status = document.getElementById("status");

async function readSamples() {
  const state = await chrome.storage.local.get(null);
  const samples = [];
  if (Array.isArray(state[LEGACY_SAMPLES_KEY])) samples.push(...state[LEGACY_SAMPLES_KEY]);
  for (const [key, value] of Object.entries(state)) {
    if (key.startsWith(SAMPLES_PREFIX) && Array.isArray(value)) samples.push(...value);
  }
  samples.sort((a, b) => (Date.parse(a.timestamp) || 0) - (Date.parse(b.timestamp) || 0));
  return samples.slice(-MAX_SAMPLES);
}

async function refresh() {
  const state = await chrome.storage.local.get([ENABLED_KEY]);
  enabledBox.checked = state[ENABLED_KEY] !== false;
  const samples = await readSamples();
  status.textContent = `${enabledBox.checked ? "הניטור פעיל" : "הניטור כבוי"}\nנשמרו מקומית ${samples.length.toLocaleString("he-IL")} דגימות.`;
}

enabledBox.addEventListener("change", async () => {
  await chrome.storage.local.set({ [ENABLED_KEY]: enabledBox.checked });
  await refresh();
});

document.getElementById("export").addEventListener("click", async () => {
  const samples = await readSamples();
  const blob = new Blob([JSON.stringify({
    schema: "pcslowwatch-browser-v1",
    exported_at: new Date().toISOString(),
    samples
  }, null, 2)], { type: "application/json" });
  const blobUrl = URL.createObjectURL(blob), date = new Date().toISOString().slice(0, 10);
  chrome.downloads.download({
    url: blobUrl,
    filename: `PCSlowWatch-browser-${date}.json`,
    saveAs: true
  }, () => {
    if (chrome.runtime.lastError) status.textContent = `ייצוא נכשל: ${chrome.runtime.lastError.message}`;
    window.setTimeout(() => URL.revokeObjectURL(blobUrl), 30000);
  });
});

document.getElementById("clear").addEventListener("click", async () => {
  if (!confirm("למחוק את כל מדידות הדפדפן שנשמרו בהרחבה?")) return;
  const state = await chrome.storage.local.get(null);
  const keys = Object.keys(state).filter(key =>
    key === LEGACY_SAMPLES_KEY || key.startsWith(SAMPLES_PREFIX) || key === LAST_CLEANUP_KEY
  );
  await chrome.storage.local.remove(keys);
  await refresh();
});

refresh().catch(() => {
  status.textContent = "לא ניתן לקרוא את מצב האחסון המקומי.";
});
