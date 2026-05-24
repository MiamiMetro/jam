#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const DEV = {
  serverHost: "127.0.0.1",
  port: process.env.JAM_DEV_PORT ?? "9999",
  serverId: "local-dev",
  secret: "dev-secret",
  codec: "opus",
  frames: "120",
  ttlMs: 10 * 60 * 1000,
  serverExe: "build/Debug/server.exe",
  clientExe: "build/Debug/client.exe",
  clients: {
    a: { room: "room-a", user: "user-a1", displayName: "User A1" },
    b: { room: "room-a", user: "user-a2", displayName: "User A2" },
  },
};

function abs(relativePath) {
  return path.resolve(repoRoot, relativePath);
}

function timestampForPath(date = new Date()) {
  return date.toISOString().replaceAll(":", "").replaceAll(".", "-");
}

function tokenFor(client) {
  const expiresAtMs = Date.now() + DEV.ttlMs;
  const nonce = crypto.randomBytes(16).toString("hex");
  const role = "performer";
  const payload = [
    "v1",
    expiresAtMs,
    DEV.serverId,
    client.room,
    client.user,
    role,
    nonce,
  ].join("|");
  const signature = crypto.createHmac("sha256", DEV.secret).update(payload).digest("hex");
  return ["v1", expiresAtMs, DEV.serverId, client.room, client.user, role, nonce, signature].join(
    ".",
  );
}

function parseArgs(argv) {
  const options = {
    seconds: 30,
    intervalSeconds: 5,
    frames: DEV.frames,
    codec: DEV.codec,
    api: "",
    latencyProfile: "",
    jitter: "",
    queueLimit: "",
    ageLimitMs: "",
    autoJitter: null,
    outDir: path.join("validation_logs", `baseline-${timestampForPath()}`),
    skipInventory: false,
    skipSmoke: false,
    skipLocal: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--seconds" && i + 1 < argv.length) {
      options.seconds = Number(argv[++i]);
    } else if (arg === "--interval-seconds" && i + 1 < argv.length) {
      options.intervalSeconds = Number(argv[++i]);
    } else if ((arg === "--frames" || arg === "--buffer-frames") && i + 1 < argv.length) {
      options.frames = argv[++i];
    } else if (arg === "--codec" && i + 1 < argv.length) {
      options.codec = argv[++i];
    } else if ((arg === "--api" || arg === "--require-api") && i + 1 < argv.length) {
      options.api = argv[++i];
    } else if ((arg === "--latency-profile" || arg === "--opus-latency-profile") && i + 1 < argv.length) {
      options.latencyProfile = argv[++i];
    } else if ((arg === "--jitter" || arg === "--opus-jitter") && i + 1 < argv.length) {
      options.jitter = argv[++i];
    } else if ((arg === "--queue-limit" || arg === "--opus-queue-limit") && i + 1 < argv.length) {
      options.queueLimit = argv[++i];
    } else if ((arg === "--age-limit-ms" || arg === "--jitter-age-limit-ms") && i + 1 < argv.length) {
      options.ageLimitMs = argv[++i];
    } else if (arg === "--auto-jitter") {
      options.autoJitter = true;
    } else if (arg === "--no-auto-jitter") {
      options.autoJitter = false;
    } else if (arg === "--out-dir" && i + 1 < argv.length) {
      options.outDir = argv[++i];
    } else if (arg === "--skip-inventory") {
      options.skipInventory = true;
    } else if (arg === "--skip-smoke") {
      options.skipSmoke = true;
    } else if (arg === "--skip-local") {
      options.skipLocal = true;
    } else if (arg === "--help" || arg === "-h") {
      usage();
      process.exit(0);
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!Number.isFinite(options.seconds) || options.seconds <= 0) {
    throw new Error("--seconds must be a positive number");
  }
  if (!Number.isFinite(options.intervalSeconds) || options.intervalSeconds <= 0) {
    throw new Error("--interval-seconds must be a positive number");
  }

  options.outDir = path.resolve(repoRoot, options.outDir);
  return options;
}

function usage() {
  console.log(
    [
      "usage:",
      "  node tools/baseline.mjs [--seconds 30] [--frames 120] [--codec opus]",
      "                          [--latency-profile low]",
      "                          [--jitter 4] [--queue-limit 24]",
      "                          [--age-limit-ms 120] [--auto-jitter|--no-auto-jitter]",
      "  node tools/baseline.mjs --skip-local",
      "",
      "Captures audio inventory, audio-open smoke output, and a local two-client",
      "baseline run using the same server/client defaults as tools/dev-jam.mjs.",
      "",
      "Outputs go under validation_logs/baseline-*/ by default.",
    ].join("\n"),
  );
}

function commandLine(command, args) {
  return [command, ...args].map((part) => (part.includes(" ") ? `"${part}"` : part)).join(" ");
}

function writeHeader(stream, title, command, args) {
  stream.write(`# ${title}\n`);
  stream.write(`# cwd: ${repoRoot}\n`);
  stream.write(`# command: ${commandLine(command, args)}\n\n`);
}

function runTee(command, args, logPath, title) {
  return new Promise((resolve) => {
    const stream = fs.createWriteStream(logPath, { flags: "a" });
    writeHeader(stream, title, command, args);
    console.log(commandLine(command, args));

    const child = spawn(command, args, {
      cwd: repoRoot,
      windowsHide: false,
      stdio: ["ignore", "pipe", "pipe"],
    });

    child.stdout.on("data", (chunk) => {
      process.stdout.write(chunk);
      stream.write(chunk);
    });
    child.stderr.on("data", (chunk) => {
      process.stderr.write(chunk);
      stream.write(chunk);
    });
    child.on("exit", (code, signal) => {
      stream.end(`\n# exit: code=${code ?? ""} signal=${signal ?? ""}\n`);
      resolve({ code: code ?? (signal ? 1 : 0), signal });
    });
    child.on("error", (error) => {
      stream.end(`\n# spawn error: ${error.message}\n`);
      resolve({ code: 1, signal: null, error });
    });
  });
}

function spawnTee(command, args, logPath, title) {
  const stream = fs.createWriteStream(logPath, { flags: "a" });
  writeHeader(stream, title, command, args);
  console.log(commandLine(command, args));

  const child = spawn(command, args, {
    cwd: repoRoot,
    windowsHide: false,
    stdio: ["ignore", "pipe", "pipe"],
  });

  child.stdout.on("data", (chunk) => {
    process.stdout.write(chunk);
    stream.write(chunk);
  });
  child.stderr.on("data", (chunk) => {
    process.stderr.write(chunk);
    stream.write(chunk);
  });
  child.on("exit", (code, signal) => {
    stream.end(`\n# exit: code=${code ?? ""} signal=${signal ?? ""}\n`);
  });
  child.on("error", (error) => {
    stream.end(`\n# spawn error: ${error.message}\n`);
  });

  return child;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function clientArgs(id, options, extraSeconds = 0) {
  const client = DEV.clients[id];
  const args = [
    "--server",
    DEV.serverHost,
    "--port",
    DEV.port,
    "--room",
    client.room,
    "--room-handle",
    client.room,
    "--user-id",
    client.user,
    "--display-name",
    client.displayName,
    "--join-token",
    tokenFor(client),
    "--codec",
    options.codec,
    "--frames",
    String(options.frames),
    "--baseline-snapshot-seconds",
    String(options.seconds + extraSeconds),
    "--baseline-snapshot-interval-seconds",
    String(options.intervalSeconds),
    "--baseline-snapshot-label",
    id,
  ];
  if (options.api) {
    args.push("--require-api", options.api);
  }
  if (options.latencyProfile) {
    args.push("--latency-profile", options.latencyProfile);
  }
  if (options.jitter) {
    args.push("--jitter", options.jitter);
  }
  if (options.queueLimit) {
    args.push("--queue-limit", options.queueLimit);
  }
  if (options.ageLimitMs) {
    args.push("--age-limit-ms", options.ageLimitMs);
  }
  if (options.autoJitter === true) {
    args.push("--auto-jitter");
  } else if (options.autoJitter === false) {
    args.push("--no-auto-jitter");
  }
  return args;
}

async function runLocalBaseline(options) {
  const serverArgs = [
    "--port",
    DEV.port,
    "--server-id",
    DEV.serverId,
    "--join-secret",
    DEV.secret,
  ];
  const server = spawnTee(
    abs(DEV.serverExe),
    serverArgs,
    path.join(options.outDir, "server.log"),
    "local baseline server",
  );

  await sleep(1500);

  const a = runTee(
    abs(DEV.clientExe),
    clientArgs("a", options),
    path.join(options.outDir, "client-a.log"),
    "local baseline client a",
  );
  const b = runTee(
    abs(DEV.clientExe),
    clientArgs("b", options, options.intervalSeconds),
    path.join(options.outDir, "client-b.log"),
    "local baseline client b",
  );

  const results = await Promise.all([a, b]);
  server.kill();
  await sleep(500);
  return results.every((result) => result.code === 0) ? 0 : 1;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  fs.mkdirSync(options.outDir, { recursive: true });

  const manifestPath = path.join(options.outDir, "manifest.txt");
  fs.writeFileSync(
    manifestPath,
    [
      "Jam RtAudio performer baseline",
      `created_at=${new Date().toISOString()}`,
      `repo=${repoRoot}`,
      `seconds=${options.seconds}`,
      `interval_seconds=${options.intervalSeconds}`,
      `frames=${options.frames}`,
      `codec=${options.codec}`,
      `api=${options.api || "default"}`,
      `latency_profile=${options.latencyProfile || "default"}`,
      `jitter=${options.jitter || "default"}`,
      `queue_limit=${options.queueLimit || "default"}`,
      `age_limit_ms=${options.ageLimitMs || "default"}`,
      `auto_jitter=${
        options.autoJitter === null ? "default" : options.autoJitter ? "true" : "false"
      }`,
      "",
      "Manual dev-jam equivalent:",
      "node tools/dev-jam.mjs server",
      "node tools/dev-jam.mjs client a",
      "node tools/dev-jam.mjs client b",
      "",
    ].join("\n"),
  );

  let exitCode = 0;
  const clientExe = abs(DEV.clientExe);

  if (!options.skipInventory) {
    const result = await runTee(
      clientExe,
      ["--list-audio-devices"],
      path.join(options.outDir, "audio-inventory.log"),
      "audio inventory",
    );
    if (result.code !== 0) {
      exitCode = result.code;
    }
  }

  if (!options.skipSmoke) {
    const smokeArgs = ["--audio-open-smoke", "--frames", String(options.frames)];
    if (options.api) {
      smokeArgs.push("--require-api", options.api);
    }
    const result = await runTee(
      clientExe,
      smokeArgs,
      path.join(options.outDir, "audio-open-smoke.log"),
      "audio open smoke",
    );
    if (result.code !== 0) {
      exitCode = result.code;
    }
  }

  if (!options.skipLocal) {
    const result = await runLocalBaseline(options);
    if (result !== 0) {
      exitCode = result;
    }
  }

  console.log(`baseline output: ${options.outDir}`);
  process.exit(exitCode);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(2);
});
