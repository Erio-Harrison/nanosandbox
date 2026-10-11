#!/usr/bin/env node
// Finds the prebuilt binary for this platform (installed as an optional
// dependency) and runs it with this process's stdio, so an MCP client talks
// to the server directly.
"use strict";

const { spawn } = require("node:child_process");
const path = require("node:path");

const PLATFORMS = {
  "darwin-arm64": "nanosandbox-mcp-darwin-arm64",
  "darwin-x64": "nanosandbox-mcp-darwin-x64",
  "linux-arm64": "nanosandbox-mcp-linux-arm64",
  "linux-x64": "nanosandbox-mcp-linux-x64",
};

function fail(message) {
  process.stderr.write(`nanosandbox-mcp: ${message}\n`);
  process.exit(2);
}

const key = `${process.platform}-${process.arch}`;
const pkg = PLATFORMS[key];
if (!pkg) {
  fail(
    `no prebuilt binary for ${key}. Supported: ${Object.keys(PLATFORMS).join(", ")} ` +
      "(Windows is not supported yet). Build from source: cargo install nanosandbox-mcp",
  );
}

let binary;
try {
  binary = path.join(
    path.dirname(require.resolve(`${pkg}/package.json`)),
    "bin",
    "nanosandbox-mcp",
  );
} catch {
  fail(
    `the ${pkg} package is missing. It's an optional dependency; reinstall without ` +
      "--omit=optional (or --no-optional), on the platform you'll run it on.",
  );
}

const child = spawn(binary, process.argv.slice(2), { stdio: "inherit" });
child.on("error", (e) => fail(`could not start ${binary}: ${e.message}`));
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => child.kill(signal));
}
child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
  } else {
    process.exit(code ?? 1);
  }
});
