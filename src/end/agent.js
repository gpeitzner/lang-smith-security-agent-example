require("dotenv").config();

const { ChatDeepSeek } = require("@langchain/deepseek");
const { tool } = require("@langchain/core/tools");
const { createToolCallingAgent, AgentExecutor } = require("langchain/agents");
const { z } = require("zod");

const { verifyIfKeyExists, setKeyValue } = require("./redis");

const readLogFileTool = tool(
  async () => {
    const fs = require("fs").promises;
    try {
      const data = await fs.readFile("./login.log", "utf-8");
      return data;
    } catch (err) {
      console.error("Error reading log file:", err);
      throw err;
    }
  },
  {
    name: "read_log_file",
    description:
      "Reads the log file and returns its content as a string. This should be called first to analyze threats.",
  },
);

const checkIpTool = tool(
  async ({ ip }) => {
    const key = `ip:${ip}`;
    const exists = await verifyIfKeyExists(key);
    return exists ? "IP is blocked" : "IP is not blocked";
  },
  {
    name: "check_ip",
    description:
      "Checks if the given IP address exists in the blocklist. Returns true if already blocked, false otherwise.",
    schema: z.object({
      ip: z.string().describe("The IP address to check."),
    }),
  },
);

const blockIpTool = tool(
  async ({ ip }) => {
    const key = `ip:${ip}`;
    await setKeyValue(key, "blocked");
    return `IP ${ip} has been blocked`;
  },
  {
    name: "block_ip",
    description:
      "Blocks the given IP address by adding it to the blocklist. Returns true if successfully blocked, false otherwise.",
    schema: z.object({
      ip: z.string().describe("The IP address to block."),
    }),
  },
);

const tools = [readLogFileTool, checkIpTool, blockIpTool];

const llm = new ChatDeepSeek({
  apiKey: process.env.DEEPSEEK_API_KEY,
});

const agent = await createToolCallingAgent({
  llm,
  tools,
  prompt:
    "You are a security agent designed to monitor and protect an API from brute-force attacks. Read log files first, analyze potential threats, check if an IP address has exceeded the request threshold and block it if necessary.",
});

const agentExecutor = new AgentExecutor({ agent, tools });

module.exports = agentExecutor;
