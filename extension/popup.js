chrome.storage.local.get({ blockCount: 0, warnCount: 0 }, (stats) => {
  document.getElementById("blocked").textContent = stats.blockCount;
  document.getElementById("warnings").textContent = stats.warnCount;
});
