const express = require("express");
const fs = require("fs");

const app = express();
const port = 3000;

const log = (message, type) => {
  if (type === "error") {
    console.error(message);
  } else {
    console.log(message);
  }
  fs.appendFileSync("log.txt", `${new Date().toISOString()} - ${message}\n`);
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

app.use(express.json());

app.post("/task", login, (req, res) => {
  if (typeof req.body.task === "string") {
    req.body.task = req.body.task.replace(/foo/g, "bar");
  }

  res.json({ task: req.body.task });
});

app.listen(port, () => {
  console.log(`API listening at http://localhost:${port}`);
});
