const express = require("express");
const cors = require("cors");
const { scanFiles, analyzeLogs, readLogs } = require("./monitor");

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());
app.use(express.static("public"));


app.post("/api/scan", (req, res) => {
  scanFiles();
  res.json({ message: "Pemindaian selesai." });
});

app.get("/api/summary", (req, res) => {
  const summary = analyzeLogs();
  res.json(summary);
});

app.get("/api/logs", (req, res) => {
  const logs = readLogs();
  res.json(logs);
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
