require("dotenv").config();

const { ChatDeepSeek } = require("@langchain/deepseek");
const { tool } = require("@langchain/core/tools");
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
    description: "Checks if the given IP address exists in the blocklist.",
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
    description: "Blocks the given IP address by adding it to the blocklist.",
    schema: z.object({
      ip: z.string().describe("The IP address to block."),
    }),
  },
);

const tools = [readLogFileTool, checkIpTool, blockIpTool];

const llm = new ChatDeepSeek({
  apiKey: process.env.DEEPSEEK_API_KEY,
});

const llmWithTools = llm.bindTools(tools);

const SYSTEM_PROMPT = `You are a security agent designed to monitor and protect an API from brute-force attacks. 
Your responsibilities are:
1. Read the log file to analyze potential threats
2. Identify IP addresses that have exceeded the request threshold
3. Check if an IP address is already blocked
4. Block malicious IP addresses

Always start by reading the log file, then analyze it for suspicious activity, and block any threatening IPs.`;

async function runAgent(input) {
  const messages = [
    { role: "system", content: SYSTEM_PROMPT },
    { role: "user", content: input },
  ];

  const response = await llmWithTools.invoke(messages);
  return response;
}

module.exports = runAgent;
