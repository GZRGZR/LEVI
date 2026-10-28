const ENABLED_KEY = "pcslowwatch_enabled", SAMPLES_KEY = "pcslowwatch_samples";
const enabledBox = document.getElementById("enabled"), status = document.getElementById("status");
async function refresh() {
  const state = await chrome.storage.local.get([ENABLED_KEY, SAMPLES_KEY]);
  enabledBox.checked = state[ENABLED_KEY] !== false;
  const samples = Array.isArray(state[SAMPLES_KEY]) ? state[SAMPLES_KEY] : [];
  status.textContent = `${enabledBox.checked ? "הניטור פעיל" : "הניטור כבוי"}\nנשמרו מקומית ${samples.length.toLocaleString("he-IL")} דגימות.`;
}
enabledBox.addEventListener("change", async () => { await chrome.storage.local.set({ [ENABLED_KEY]: enabledBox.checked }); await refresh(); });
document.getElementById("export").addEventListener("click", async () => {
  const state = await chrome.storage.local.get([SAMPLES_KEY]), samples = Array.isArray(state[SAMPLES_KEY]) ? state[SAMPLES_KEY] : [];
  const blob = new Blob([JSON.stringify({ schema: "pcslowwatch-browser-v1", exported_at: new Date().toISOString(), samples }, null, 2)], { type: "application/json" });
  const blobUrl = URL.createObjectURL(blob), date = new Date().toISOString().slice(0, 10);
  chrome.downloads.download({ url: blobUrl, filename: `PCSlowWatch-browser-${date}.json`, saveAs: true }, () => {
    if (chrome.runtime.lastError) status.textContent = `ייצוא נכשל: ${chrome.runtime.lastError.message}`;
    window.setTimeout(() => URL.revokeObjectURL(blobUrl), 30000);
  });
});
document.getElementById("clear").addEventListener("click", async () => {
  if (!confirm("למחוק את כל מדידות הדפדפן שנשמרו בהרחבה?")) return;
  await chrome.storage.local.set({ [SAMPLES_KEY]: [] }); await refresh();
});
refresh().catch(() => { status.textContent = "לא ניתן לקרוא את מצב האחסון המקומי."; });
