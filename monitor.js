const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const MONITOR_DIR = "./secure_files";
const HASH_DB = "./hash_db.json";
const LOG_FILE = "./security_log.txt";

function getFileHash(filePath) {
  const fileBuffer = fs.readFileSync(filePath);
  const hashSum = crypto.createHash("sha256");
  hashSum.update(fileBuffer);
  return hashSum.digest("hex");
}

function logEvent(level, message) {
  const timestamp = new Date().toLocaleString("sv-SE", {
    timeZone: "Asia/Jakarta",
  }).replace("T", " ").split(".")[0];
  const logMessage = `[${timestamp}] ${level}: ${message}\n`;
  fs.appendFileSync(LOG_FILE, logMessage);
  console.log(logMessage.trim());
}

let hashDB = {};
if (fs.existsSync(HASH_DB)) {
  hashDB = JSON.parse(fs.readFileSync(HASH_DB, "utf-8"));
  logEvent("INFO", "Loaded existing hash database.");
} else {
  const currentFiles = fs.existsSync(MONITOR_DIR) ? fs.readdirSync(MONITOR_DIR) : [];
  currentFiles.forEach(file => {
    const filePath = path.join(MONITOR_DIR, file);
    if (fs.lstatSync(filePath).isFile()) {
      hashDB[file] = getFileHash(filePath);
    }
  });
  fs.writeFileSync(HASH_DB, JSON.stringify(hashDB, null, 2));
  logEvent("INFO", "Initialized hash database with current files.");
}

function scanFiles() {
  if (!fs.existsSync(MONITOR_DIR)) {
    logEvent("ERROR", `Monitored directory ${MONITOR_DIR} does not exist.`);
    return;
  }

  const currentFiles = fs.readdirSync(MONITOR_DIR);
  const currentHashes = {};

  currentFiles.forEach(file => {
    const filePath = path.join(MONITOR_DIR, file);
    if (fs.lstatSync(filePath).isDirectory()) return;
    currentHashes[file] = getFileHash(filePath);
  });

  currentFiles.forEach(file => {
    if (!hashDB[file]) {
      logEvent("ALERT", `Unknown file "${file}" detected.`);
    } else if (hashDB[file] !== currentHashes[file]) {
      logEvent("WARNING", `File "${file}" integrity failed!`);
    } else {
      logEvent("INFO", `File "${file}" verified OK.`);
    }
  });

  for (const file in hashDB) {
    if (!currentHashes[file]) {
      logEvent("ALERT", `File "${file}" has been deleted!`);
    }
  }
}

function analyzeLogs() {
  if (!fs.existsSync(LOG_FILE))
    return { safeCount: 0, failedCount: 0, lastAnomaly: "Belum ada log." };

  const lines = fs.readFileSync(LOG_FILE, "utf-8").split("\n").filter(Boolean);
  const status = {};

  for (const l of lines) {
    const name = l.match(/\(([^)]+)\)/)?.[1] || l.match(/"([^"]+)"/)?.[1];
    if (!name) continue;
    if (/verified OK/i.test(l)) status[name] = "safe";
    else if (/failed/i.test(l)) status[name] = "failed";
    else if (/ALERT/i.test(l)) status[name] = "alert";
  }

  const vals = Object.values(status);
  return {
    safeCount: vals.filter((v) => v === "safe").length,
    failedCount: vals.filter((v) => v === "failed").length,
    lastAnomaly:
      lines.findLast((l) => l.includes("ALERT"))?.match(/\[(.*?)\]/)?.[1] ||
      "Tidak ada anomali.",
  };
}

function readLogs() {
  if (!fs.existsSync(LOG_FILE)) return [];
  return fs.readFileSync(LOG_FILE, "utf-8").split("\n").filter(Boolean);
}

module.exports = { scanFiles, analyzeLogs, readLogs };
