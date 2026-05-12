#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const defaults = {
  buildDir: "build",
  destination: path.join("..", "jam-app", "apps", "desktop", "resources", "client"),
};

function parseArgs(argv) {
  const options = { ...defaults };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--build-dir" && argv[i + 1]) {
      options.buildDir = argv[++i];
    } else if ((arg === "--out" || arg === "--destination") && argv[i + 1]) {
      options.destination = argv[++i];
    } else if (arg === "--help" || arg === "-h") {
      usage();
      process.exit(0);
    } else {
      console.error(`unknown argument: ${arg}`);
      usage();
      process.exit(2);
    }
  }
  return options;
}

function usage() {
  console.log(
    [
      "usage:",
      "  node tools/build-release-client.mjs",
      "  node tools/build-release-client.mjs --build-dir build --out ../jam-app/apps/desktop/resources/client",
      "",
      "Builds the native client in Release mode and copies it to the desktop app resources folder.",
    ].join("\n"),
  );
}

function run(command, args, cwd = repoRoot) {
  console.log([command, ...args].join(" "));
  const result = spawnSync(command, args, {
    cwd,
    stdio: "inherit",
  });
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

function existingFile(candidates) {
  return candidates.find((candidate) => fs.existsSync(candidate) && fs.statSync(candidate).isFile());
}

function clientCandidates(buildPath) {
  const exe = process.platform === "win32" ? "client.exe" : "client";
  return [
    path.join(buildPath, "Release", exe),
    path.join(buildPath, "RelWithDebInfo", exe),
    path.join(buildPath, exe),
  ];
}

const options = parseArgs(process.argv.slice(2));
const buildPath = path.resolve(repoRoot, options.buildDir);
const destinationPath = path.resolve(repoRoot, options.destination);

if (!fs.existsSync(path.join(buildPath, "CMakeCache.txt"))) {
  const configureArgs = ["-S", repoRoot, "-B", buildPath];
  if (process.platform !== "win32") {
    configureArgs.push("-DCMAKE_BUILD_TYPE=Release");
  }
  run("cmake", configureArgs);
}

run("cmake", ["--build", buildPath, "--config", "Release", "--target", "client"]);

const clientPath = existingFile(clientCandidates(buildPath));
if (!clientPath) {
  console.error("Release client executable not found. Checked:");
  for (const candidate of clientCandidates(buildPath)) {
    console.error(`  ${candidate}`);
  }
  process.exit(3);
}

fs.mkdirSync(destinationPath, { recursive: true });
const destinationFile = path.join(destinationPath, path.basename(clientPath));
fs.copyFileSync(clientPath, destinationFile);

console.log(`Copied ${clientPath} to ${destinationFile}`);
