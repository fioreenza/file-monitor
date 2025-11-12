const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const chokidar = require("chokidar");

const MONITOR_DIR = path.resolve("./secure_files");
const HASH_DB = path.resolve("./hash_db.json");
const LOG_FILE = path.resolve("./security_log.txt");

function getFileHash(filePath) {
  try {
    const fileBuffer = fs.readFileSync(filePath);
    const hashSum = crypto.createHash("sha256");
    hashSum.update(fileBuffer);
    return hashSum.digest("hex");
  } catch (error) {
    logEvent(
      "ERROR",
      `Could not read file "${path.relative(
        MONITOR_DIR,
        filePath
      )}". It may have been deleted.`
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


function getAllFiles(dirPath, arrayOfFiles = []) {
  const files = fs.readdirSync(dirPath);

  files.forEach((file) => {
    const fullPath = path.join(dirPath, file);
    if (fs.statSync(fullPath).isDirectory()) {
      getAllFiles(fullPath, arrayOfFiles);
    } else {
      arrayOfFiles.push(fullPath);
    }
  });

  return arrayOfFiles;
}

let hashDB = {};
let liveState = {};

function initializeBaseline() {
  if (fs.existsSync(HASH_DB)) {
    hashDB = JSON.parse(fs.readFileSync(HASH_DB, "utf-8"));
    logEvent("INFO", "Loaded security baseline from hash_db.json.");
  } else {
    logEvent("INFO", "No baseline found. Creating new security baseline...");
    if (!fs.existsSync(MONITOR_DIR)) {
      fs.mkdirSync(MONITOR_DIR, { recursive: true });
    }
    const allFiles = getAllFiles(MONITOR_DIR);
    allFiles.forEach((filePath) => {
      const relativePath = path.relative(MONITOR_DIR, filePath);
      hashDB[relativePath] = getFileHash(filePath);
    });
    fs.writeFileSync(HASH_DB, JSON.stringify(hashDB, null, 2));
    logEvent("INFO", "Initialized new security baseline in hash_db.json.");
  }
  liveState = JSON.parse(JSON.stringify(hashDB));
}

function startMonitoring(onChangeCallback) {
  initializeBaseline();

  const watcher = chokidar.watch(MONITOR_DIR, {
    persistent: true,
    ignoreInitial: true,
    ignored: /(^|[\/\\])\../,
  });

  logEvent("INFO", `Real-time monitoring started on: ${MONITOR_DIR}`);

  watcher
    .on("add", (filePath) => {
      const relativePath = path.relative(MONITOR_DIR, filePath);
      logEvent("ALERT", `New file detected: "${relativePath}".`);
      const hash = getFileHash(filePath);
      if (hash) {
        liveState[relativePath] = hash;
      }
      onChangeCallback();
    })
    .on("change", (filePath) => {
      const relativePath = path.relative(MONITOR_DIR, filePath);
      const newHash = getFileHash(filePath);
      if (newHash && liveState[relativePath] !== newHash) {
        logEvent("WARNING", `File modified: "${relativePath}". Integrity failed.`);
        liveState[relativePath] = newHash;
        onChangeCallback();
      } else if (!newHash) {
        delete liveState[relativePath];
        onChangeCallback();
      }
    })
    .on("unlink", (filePath) => {
      const relativePath = path.relative(MONITOR_DIR, filePath);
      if (liveState[relativePath]) {
        logEvent("ALERT", `File deleted: "${relativePath}".`);
        delete liveState[relativePath];
        onChangeCallback();
      }
    })
    .on("addDir", (dirPath) => {
      const relativePath = path.relative(MONITOR_DIR, dirPath);
      logEvent("INFO", `Directory added: "${relativePath}".`);
      onChangeCallback();
    })
    .on("unlinkDir", (dirPath) => {
      const relativePath = path.relative(MONITOR_DIR, dirPath);
      logEvent("ALERT", `Directory deleted: "${relativePath}".`);
      Object.keys(liveState).forEach((file) => {
        if (file.startsWith(relativePath + path.sep)) {
          delete liveState[file];
        }
      });
      onChangeCallback();
    })
    .on("error", (error) => logEvent("ERROR", `Watcher error: ${error}`));
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

module.exports = { startMonitoring, analyzeLogs, readLogs };