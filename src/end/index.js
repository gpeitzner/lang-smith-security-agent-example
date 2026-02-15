const express = require("express");
const fs = require("fs");

const { verifyIfKeyExists } = require("./redis");
const runAgent = require("./agent");

const app = express();
const port = 3000;

const log = (message, type) => {
  if (type === "error") {
    console.error(message);
  } else {
    console.log(message);
  }
  fs.appendFileSync("login.log", `${new Date().toISOString()} - ${message}\n`);
};

app.use(express.json());

const guardian = async (req, res, next) => {
  const clientIp = req.headers["x-forwarded-for"];
  const key = `ip:${clientIp}`;
  const isBlocked = await verifyIfKeyExists(key);
  if (isBlocked) {
    log(`Blocked login attempt from ${clientIp}`, "error");
    return res.status(403).send("Forbidden");
  }
  next();
};

const login = (req, res, next) => {
  const whitelist = JSON.parse(fs.readFileSync("whitelist.json", "utf-8"));
  const clientIp = req.headers["x-forwarded-for"];

  if (whitelist.includes(clientIp)) {
    log(`Login attempt from ${clientIp} - SUCCESS`, "info");
    next();
  } else {
    log(`Login attempt from ${clientIp} - FAILED`, "error");
    res.status(403).send("Forbidden");
  }
};

app.post("/task", guardian, login, (req, res) => {
  if (typeof req.body.task === "string") {
    req.body.task = req.body.task.replace(/foo/g, "bar");
  }

  res.json({ task: req.body.task });
});

const runSecurityAgent = async () => {
  try {
    log("Running security agent...", "info");
    const result = await runAgent(
      "Analyze security logs and block malicious IPs attempting to access the API",
    );
    log(`Security agent completed: ${result}`, "info");
  } catch (err) {
    log(`Security agent error: ${err.message}`, "error");
  }
};

runSecurityAgent();

setInterval(runSecurityAgent, 600000);

app.listen(port, () => {
  console.log(`API listening at http://localhost:${port}`);
});
