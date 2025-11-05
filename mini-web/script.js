async function loadSummary() {
  const res = await fetch("http://localhost:3000/api/summary");
  const data = await res.json();
  document.getElementById("safeCount").innerText = data.safeCount;
  document.getElementById("failedCount").innerText = data.failedCount;
  document.getElementById("lastAnomaly").innerText = data.lastAnomaly;
}

async function loadLogs() {
  const res = await fetch("http://localhost:3000/api/logs");
  const data = await res.json();
  document.getElementById("logContent").innerText = data.join("\n");
}

async function runScan() {
  document.getElementById("scanBtn").disabled = true;
  document.getElementById("scanBtn").innerText = "⏳ Memindai...";
  await fetch("http://localhost:3000/api/scan", { method: "POST" });
  await loadSummary();
  await loadLogs();
  document.getElementById("scanBtn").innerText = "🔄 Jalankan Scan";
  document.getElementById("scanBtn").disabled = false;
}

document.getElementById("scanBtn").addEventListener("click", runScan);

loadSummary();
loadLogs();
