const express = require("express");
const cors = require("cors");
const { startMonitoring, analyzeLogs, readLogs } = require("./monitor");

const app = express();
const PORT = 4000;

let clients = [];

app.use(cors());
app.use(express.json());
app.use(express.static("public"));

app.get("/api/events", (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  const clientId = Date.now();
  clients.push({ id: clientId, res });
  console.log(`Client ${clientId} connected`);

  sendUpdate();

  req.on("close", () => {
    clients = clients.filter((client) => client.id !== clientId);
    console.log(`Client ${clientId} disconnected`);
  });
});

app.get("/api/summary", (req, res) => {
  const summary = analyzeLogs();
  res.json(summary);
});

app.get("/api/logs", (req, res) => {
  const logs = readLogs();
  res.json(logs);
});

function sendUpdate() {
  const summary = analyzeLogs();
  const logs = readLogs();
  const data = { summary, logs };

  for (const client of clients) {
    client.res.write(`data: ${JSON.stringify(data)}\n\n`);
  }
}

startMonitoring(sendUpdate);

app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);
