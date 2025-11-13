function flashElement(elementId) {
  const element = document.getElementById(elementId);
  if (element) {
    element.classList.add("flash");
    setTimeout(() => {
      element.classList.remove("flash");
    }, 700);
  }
}

function updateUI(summary, logs) {
  const safeCountEl = document.getElementById("safeCount");
  const failedCountEl = document.getElementById("failedCount");
  const lastAnomalyEl = document.getElementById("lastAnomaly");
  const logContentEl = document.getElementById("logContent");

  if (safeCountEl.innerText !== summary.safeCount.toString()) {
    safeCountEl.innerText = summary.safeCount;
    flashElement("safe-card");
  }

  if (failedCountEl.innerText !== summary.failedCount.toString()) {
    failedCountEl.innerText = summary.failedCount;
    flashElement("failed-card");
  }

  if (lastAnomalyEl.innerText !== summary.lastAnomaly) {
    lastAnomalyEl.innerText = summary.lastAnomaly;
    flashElement("anomaly-card");
  }

  const newLogContent = logs.join("\n");
  if (logContentEl.innerText !== newLogContent) {
    logContentEl.innerText = newLogContent;

    logContentEl.scrollTop = logContentEl.scrollHeight;
    flashElement("logs-section");
  }
}

async function loadInitialData() {
  try {
    const summaryRes = await fetch("http://localhost:4000/api/summary");
    const summary = await summaryRes.json();
    const logsRes = await fetch("http://localhost:4000/api/logs");
    const logs = await logsRes.json();
    updateUI(summary, logs);
  } catch (error) {
    document.getElementById("logContent").innerText =
      "Gagal terhubung ke server. Pastikan server sudah berjalan.";
  }
}

function startLiveUpdates() {
  const eventSource = new EventSource("http://localhost:4000/api/events");

  eventSource.onmessage = function (event) {
    console.log("Menerima pembaruan dari server...");
    const data = JSON.parse(event.data);
    updateUI(data.summary, data.logs);
  };

  eventSource.onerror = function (err) {
    console.error("EventSource gagal:", err);
    eventSource.close();
    setTimeout(startLiveUpdates, 5000);
  };
}

document.getElementById("uploadForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const fileInput = document.getElementById("fileInput");
  const passwordInput = document.getElementById("passwordInput");
  const statusEl = document.getElementById("uploadStatus");

  if (!fileInput.files.length) {
    statusEl.textContent = "Pilih file terlebih dahulu.";
    return;
  }

  const formData = new FormData();
  formData.append("file", fileInput.files[0]);
  formData.append("password", passwordInput.value);

  statusEl.textContent = "Mengunggah file...";

  try {
    const res = await fetch("http://localhost:4000/api/upload", {
      method: "POST",
      body: formData,
    });

    const result = await res.json();
    statusEl.textContent = result.message;

    if (res.ok) {
      flashElement("safe-card");
    } else {
      flashElement("failed-card");
    }
  } catch (err) {
    statusEl.textContent = "Gagal mengunggah file ke server.";
  }
});

loadInitialData();
startLiveUpdates();
