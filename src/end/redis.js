const { createClient } = require("redis");

const client = createClient();

client.on("error", (err) => console.error("Redis Client Error", err));

let isConnected = false;

const connectRedis = async () => {
  if (!isConnected) {
    await client.connect();
    isConnected = true;
  }
};

const verifyIfKeyExists = async (key) => {
  try {
    await connectRedis();
    const value = await client.get(key);
    return value !== null;
  } catch (err) {
    console.error("Error verifying key:", err);
    throw err;
  }
};

const setKeyValue = async (key, value) => {
  try {
    await connectRedis();
    await client.set(key, value);
  } catch (err) {
    console.error("Error setting key:", err);
    throw err;
  }
};

module.exports = {
  verifyIfKeyExists,
  setKeyValue,
  connectRedis,
};
