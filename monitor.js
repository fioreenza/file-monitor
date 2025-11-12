const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const MONITOR_DIR = "./secure_files";
const HASH_DB = "./hash_db.json";
const LOG_FILE = "./security_log.txt";

function getFileHash(filePath) {
  try {
    const fileBuffer = fs.readFileSync(filePath);
    const hashSum = crypto.createHash("sha256");
    hashSum.update(fileBuffer);
    return hashSum.digest("hex");
  } catch (error) {
    logEvent(
      "ERROR",
      `Could not read file "${path.basename(
        filePath
      )}". It might be in use or deleted.`
    );
    return null;
  }
}

function logEvent(level, message) {
  const timestamp = new Date()
    .toLocaleString("sv-SE", {
      timeZone: "Asia/Jakarta",
    })
    .replace("T", " ")
    .split(".")[0];
  const logMessage = `[${timestamp}] ${level}: ${message}\n`;
  fs.appendFileSync(LOG_FILE, logMessage);
  console.log(logMessage.trim());
}

let hashDB = {};
let liveState = {};

if (fs.existsSync(HASH_DB)) {
  hashDB = JSON.parse(fs.readFileSync(HASH_DB, "utf-8"));
  logEvent("INFO", "Loaded security baseline from hash_db.json.");
} else {
  const currentFiles = fs.existsSync(MONITOR_DIR)
    ? fs.readdirSync(MONITOR_DIR)
    : [];
  currentFiles.forEach((file) => {
    const filePath = path.join(MONITOR_DIR, file);
    if (fs.lstatSync(filePath).isFile()) {
      hashDB[file] = getFileHash(filePath);
    }
  });
  fs.writeFileSync(HASH_DB, JSON.stringify(hashDB, null, 2));
  logEvent("INFO", "Initialized new security baseline in hash_db.json.");
}

liveState = JSON.parse(JSON.stringify(hashDB));

function checkForChanges() {
  if (!fs.existsSync(MONITOR_DIR)) {
    logEvent("ERROR", `Monitored directory ${MONITOR_DIR} does not exist.`);
    return false;
  }

  let changesDetected = false;
  const currentFiles = fs.readdirSync(MONITOR_DIR);
  const currentHashes = {};

  currentFiles.forEach((file) => {
    const filePath = path.join(MONITOR_DIR, file);
    if (fs.lstatSync(filePath).isFile()) {
      const hash = getFileHash(filePath);
      if (hash) currentHashes[file] = hash;
    }
  });

  for (const file in currentHashes) {
    if (!liveState[file]) {
      logEvent("ALERT", `New file detected: "${file}".`);
      liveState[file] = currentHashes[file];
      changesDetected = true;
    } else if (liveState[file] !== currentHashes[file]) {
      logEvent("WARNING", `File modified: "${file}". Integrity failed.`);
      liveState[file] = currentHashes[file];
      changesDetected = true;
    }
  }

  for (const file in liveState) {
    if (!currentHashes[file]) {
      logEvent("ALERT", `File deleted: "${file}".`);
      delete liveState[file];
      changesDetected = true;
    }
  }

  return changesDetected;
}

function analyzeLogs() {
  if (!fs.existsSync(LOG_FILE))
    return { safeCount: 0, failedCount: 0, lastAnomaly: "Belum ada log." };

  const lines = fs.readFileSync(LOG_FILE, "utf-8").split("\n").filter(Boolean);
  let safeCount = Object.keys(hashDB).length;
  let failedCount = 0;

  const fileStatus = {};

  lines.forEach((line) => {
    const fileMatch = line.match(/"(.*?)"/);
    if (!fileMatch) return;
    const file = fileMatch[1];

    if (line.includes("WARNING") || line.includes("ALERT")) {
      fileStatus[file] = "failed";
    }
  });

  failedCount = Object.keys(fileStatus).length;
  safeCount = Math.max(0, Object.keys(hashDB).length - failedCount);

  return {
    safeCount: safeCount,
    failedCount: failedCount,
    lastAnomaly:
      lines
        .findLast((l) => l.includes("ALERT") || l.includes("WARNING"))
        ?.match(/\[(.*?)\]/)?.[1] || "Tidak ada anomali.",
  };
}

function readLogs() {
  if (!fs.existsSync(LOG_FILE)) return [];
  return fs.readFileSync(LOG_FILE, "utf-8").split("\n").filter(Boolean);
}

module.exports = { checkForChanges, analyzeLogs, readLogs };
