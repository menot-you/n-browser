#!/usr/bin/env node
const { spawnSync } = require("node:child_process");
const process = require("node:process");

const args = process.argv.slice(2);

// Try "uv run nbrowser" first, then fall back to "nbrowser"
let res = spawnSync("uv", ["run", "nbrowser", ...args], { stdio: "inherit" });
if (res.error && res.error.code === "ENOENT") {
  res = spawnSync("nbrowser", args, { stdio: "inherit" });
}

if (res.error) {
  console.error(`Failed to execute nbrowser: ${res.error.message}`);
  process.exit(1);
}

process.exit(res.status ?? (res.signal ? 1 : 0));
