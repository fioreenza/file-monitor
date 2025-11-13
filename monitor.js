const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const multer = require("multer");
const chokidar = require("chokidar");

const MONITOR_DIR = path.resolve("./secure_files");
const HASH_DB = path.resolve("./hash_db.json");
const LOG_FILE = path.resolve("./security_log.txt");
const PASSWORD = "admin123";
const UPLOAD_DIR = MONITOR_DIR;

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  },
});
const upload = multer({ storage });

function logEvent(level, message) {
  const timestamp = new Date()
    .toLocaleString("sv-SE", { timeZone: "Asia/Jakarta" })
    .replace("T", " ")
    .split(".")[0];
  const logMessage = `[${timestamp}] ${level}: ${message}\n`;
  fs.appendFileSync(LOG_FILE, logMessage);
  console.log(logMessage.trim());
}

function getFileHash(filePath) {
  try {
    const fileBuffer = fs.readFileSync(filePath);
    const hashSum = crypto.createHash("sha256");
    hashSum.update(fileBuffer);
    return hashSum.digest("hex");
  } catch (error) {
    logEvent("ERROR", `Could not read file "${path.relative(MONITOR_DIR, filePath)}".`);
    return null;
  }
}

function getAllFiles(dirPath, arrayOfFiles = []) {
  if (!fs.existsSync(dirPath)) return arrayOfFiles;
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
    try {
      hashDB = JSON.parse(fs.readFileSync(HASH_DB, "utf-8"));
      logEvent("INFO", "Loaded security baseline from hash_db.json.");
    } catch (e) {
      logEvent("ERROR", "Failed to parse hash_db.json. Reinitializing baseline.");
      hashDB = {};
    }
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

function handleFileUpload(req, res, sendUpdate) {
  const userPassword = req.body.password;
  const file = req.file;

  if (!file) {
    return res.status(400).json({ message: "Tidak ada file yang diupload." });
  }

  if (userPassword !== PASSWORD) {
    logEvent("ALERT", `File "${file.originalname}" uploaded with incorrect password (anomaly).`);
    sendUpdate();
    return res.status(403).json({
      message: "Password salah! File disimpan tapi ditandai anomali (ALERT).",
    });
  }

  const relativePath = path.relative(MONITOR_DIR, file.path);
  const hash = getFileHash(file.path);
  if (hash) {
    hashDB[relativePath] = hash;
    fs.writeFileSync(HASH_DB, JSON.stringify(hashDB, null, 2));
    logEvent("INFO", `File "${file.originalname}" verified OK.`);
    liveState[relativePath] = hash;
    sendUpdate();
    return res.json({ message: "File berhasil diupload dan diverifikasi OK." });
  } else {
    logEvent("ERROR", `Unknown problem reading uploaded file "${file.originalname}".`);
    sendUpdate();
    return res.status(500).json({ message: "Gagal memproses file yang diupload." });
  }
}

function startMonitoring(onChangeCallback) {
  initializeBaseline();

  const watcher = chokidar.watch(MONITOR_DIR, {
    persistent: true,
    ignoreInitial: false,
    ignored: /(^|[\/\\])\../,
  });

  logEvent("INFO", `Real-time monitoring started on: ${MONITOR_DIR}`);

  watcher
    .on("add", (filePath) => {
      const relativePath = path.relative(MONITOR_DIR, filePath);
      const hash = getFileHash(filePath);

      if (!hashDB[relativePath]) {
        logEvent("ALERT", `Unknown file "${relativePath}" detected.`);
      } else if (hash === hashDB[relativePath]) {
        logEvent("INFO", `File "${relativePath}" verified OK.`);
      } else {
        logEvent("WARNING", `File "${relativePath}" integrity failed!`);
      }

      liveState[relativePath] = hash;
      onChangeCallback();
    })
    .on("change", (filePath) => {
      const relativePath = path.relative(MONITOR_DIR, filePath);
      const newHash = getFileHash(filePath);

      if (!hashDB[relativePath]) {
        logEvent("ALERT", `Unknown file "${relativePath}" detected.`);
      } else if (hashDB[relativePath] !== newHash) {
        logEvent("WARNING", `File "${relativePath}" integrity failed!`);
      } else {
        logEvent("INFO", `File "${relativePath}" verified OK.`);
      }

      liveState[relativePath] = newHash;
      onChangeCallback();
    })
    .on("unlink", (filePath) => {
      const relativePath = path.relative(MONITOR_DIR, filePath);
      logEvent("ALERT", `File "${relativePath}" deleted.`);
      delete liveState[relativePath];
      onChangeCallback();
    })
    .on("error", (error) => {
      logEvent("ERROR", `Watcher error: ${error}`);
    });
}

function analyzeLogs() {
  if (!fs.existsSync(LOG_FILE))
    return { safeCount: 0, failedCount: 0, anomalyCount: 0, lastAnomaly: "Belum ada log." };

  const lines = fs.readFileSync(LOG_FILE, "utf-8").split("\n").filter(Boolean);

  const failedSet = new Set();   
  const anomalySet = new Set();  

  lines.forEach((line) => {
    const match = line.match(/"(.*?)"/);
    if (!match) return;
    const file = match[1];

    if (line.includes("WARNING")) {
      failedSet.add(file);
    } else if (line.includes("ALERT")) {
      anomalySet.add(file); 
    }
  });

  const failedCount = failedSet.size; 
  const anomalyCount = anomalySet.size; 
  const safeCount = Math.max(0, Object.keys(hashDB).length - failedCount);

  const lastAnomLine =
    lines.findLast((l) => l.includes("ALERT") || l.includes("WARNING")) || null;
  const lastAnomaly =
    lastAnomLine?.match(/\[(.*?)\]/)?.[1] || "Tidak ada anomali.";

  return {
    safeCount,
    failedCount,
    anomalyCount,
    lastAnomaly,
  };
}

function readLogs() {
  if (!fs.existsSync(LOG_FILE)) return [];
  return fs.readFileSync(LOG_FILE, "utf-8").split("\n").filter(Boolean);
}

module.exports = {
  startMonitoring,
  analyzeLogs,
  readLogs,
  handleFileUpload,
  upload,
};
