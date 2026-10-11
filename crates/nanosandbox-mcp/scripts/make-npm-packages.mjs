#!/usr/bin/env node
// Assembles the npm packages for one release from built binaries.
//
//   node scripts/make-npm-packages.mjs <binaries-dir> <out-dir>
//
// <binaries-dir> holds one file per target, named as in TARGETS below
// (e.g. nanosandbox-mcp-aarch64-apple-darwin). Writes <out-dir>/main and
// <out-dir>/<platform-package> for each binary found. Every version comes
// from Cargo.toml, so the packages can't drift from the crate.
import { chmodSync, copyFileSync, cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const crate = resolve(here, "..");

const TARGETS = [
  { target: "aarch64-apple-darwin", os: "darwin", cpu: "arm64" },
  { target: "x86_64-apple-darwin", os: "darwin", cpu: "x64" },
  { target: "aarch64-unknown-linux-gnu", os: "linux", cpu: "arm64", libc: "glibc" },
  { target: "x86_64-unknown-linux-gnu", os: "linux", cpu: "x64", libc: "glibc" },
];

const [binDir, outDir] = process.argv.slice(2).map((p) => p && resolve(p));
if (!binDir || !outDir) {
  console.error("usage: make-npm-packages.mjs <binaries-dir> <out-dir>");
  process.exit(2);
}

const cargo = readFileSync(join(crate, "Cargo.toml"), "utf8");
const version = cargo.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
if (!version) throw new Error("no version in Cargo.toml");

const common = {
  version,
  license: "MIT",
  repository: { type: "git", url: "https://github.com/Erio-Harrison/nanosandbox.git" },
  homepage: "https://github.com/Erio-Harrison/nanosandbox/tree/master/crates/nanosandbox-mcp",
};

const optionalDependencies = {};
const built = [];
for (const t of TARGETS) {
  const name = `nanosandbox-mcp-${t.os}-${t.cpu}`;
  const source = join(binDir, `nanosandbox-mcp-${t.target}`);
  if (!existsSync(source)) {
    console.warn(`skipping ${name}: no ${source}`);
    continue;
  }
  const dir = join(outDir, name);
  mkdirSync(join(dir, "bin"), { recursive: true });
  const dest = join(dir, "bin", "nanosandbox-mcp");
  copyFileSync(source, dest);
  chmodSync(dest, 0o755);
  const pkg = {
    name,
    ...common,
    description: `The ${t.os} ${t.cpu} binary of nanosandbox-mcp`,
    os: [t.os],
    cpu: [t.cpu],
    ...(t.libc ? { libc: [t.libc] } : {}),
    files: ["bin/"],
  };
  writeFileSync(join(dir, "package.json"), JSON.stringify(pkg, null, 2) + "\n");
  optionalDependencies[name] = version;
  built.push(name);
}
if (built.length === 0) throw new Error(`no binaries found in ${binDir}`);

const main = join(outDir, "main");
mkdirSync(join(main, "bin"), { recursive: true });
copyFileSync(join(crate, "npm", "bin", "nanosandbox-mcp.js"), join(main, "bin", "nanosandbox-mcp.js"));
chmodSync(join(main, "bin", "nanosandbox-mcp.js"), 0o755);
copyFileSync(join(crate, "README.md"), join(main, "README.md"));
writeFileSync(
  join(main, "package.json"),
  JSON.stringify(
    {
      name: "nanosandbox-mcp",
      ...common,
      description: "MCP server (stdio) that runs commands in a nanosandbox sandbox",
      keywords: ["mcp", "sandbox", "agent", "security", "isolation"],
      bin: { "nanosandbox-mcp": "bin/nanosandbox-mcp.js" },
      files: ["bin/", "README.md"],
      engines: { node: ">= 18" },
      os: ["darwin", "linux"],
      optionalDependencies,
    },
    null,
    2,
  ) + "\n",
);
console.log(`version ${version}: ${built.join(", ")}, main`);
