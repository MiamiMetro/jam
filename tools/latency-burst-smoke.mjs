#!/usr/bin/env node

import dgram from "node:dgram";
import { spawn } from "node:child_process";

function usage(message) {
  if (message) {
    console.error(message);
  }
  console.error(
    "Usage: latency-burst-smoke.mjs --server-exe <path> --proxy-exe <path> --probe-exe <path>",
  );
  process.exit(message ? 2 : 0);
}

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      usage();
    }
    if (!arg.startsWith("--") || i + 1 >= argv.length) {
      usage(`unknown or incomplete argument: ${arg}`);
    }
    args[arg.slice(2)] = argv[++i];
  }
  for (const required of ["server-exe", "proxy-exe", "probe-exe"]) {
    if (!args[required]) {
      usage(`missing --${required}`);
    }
  }
  return args;
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function reserveUdpPort() {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket("udp4");
    socket.once("error", reject);
    socket.bind(0, "127.0.0.1", () => {
      const port = socket.address().port;
      socket.close(() => resolve(port));
    });
  });
}

function spawnLogged(name, command, args) {
  const child = spawn(command, args, {
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => process.stdout.write(`[${name}] ${chunk}`));
  child.stderr.on("data", (chunk) => process.stderr.write(`[${name}] ${chunk}`));
  return child;
}

function waitForOutput(child, pattern, timeoutMs, name) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`${name} did not report readiness within ${timeoutMs} ms`));
    }, timeoutMs);

    const onData = (chunk) => {
      if (pattern.test(chunk)) {
        cleanup();
        resolve();
      }
    };
    const onExit = (code, signal) => {
      cleanup();
      reject(new Error(`${name} exited before ready: code=${code} signal=${signal}`));
    };
    const cleanup = () => {
      clearTimeout(timer);
      child.stdout.off("data", onData);
      child.stderr.off("data", onData);
      child.off("exit", onExit);
    };

    child.stdout.on("data", onData);
    child.stderr.on("data", onData);
    child.once("exit", onExit);
  });
}

function runChecked(name, command, args) {
  return new Promise((resolve, reject) => {
    const child = spawnLogged(name, command, args);
    child.on("error", reject);
    child.on("exit", (code, signal) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`${name} failed: code=${code} signal=${signal}`));
    });
  });
}

function stopChild(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) {
    return;
  }
  child.kill();
}

const args = parseArgs(process.argv);
const serverPort = await reserveUdpPort();
let proxyPort = await reserveUdpPort();
while (proxyPort === serverPort) {
  proxyPort = await reserveUdpPort();
}
let server;
let proxy;

try {
  server = spawnLogged("server", args["server-exe"], [
    "--port",
    String(serverPort),
    "--allow-insecure-dev-joins",
  ]);
  await waitForOutput(server, /SFU server ready/, 5000, "server");

  proxy = spawnLogged("proxy", args["proxy-exe"], [
    "--listen-host",
    "127.0.0.1",
    "--listen-port",
    String(proxyPort),
    "--server",
    "127.0.0.1",
    "--server-port",
    String(serverPort),
    "--burst-every",
    "100",
    "--burst-count",
    "10",
    "--burst-offset",
    "30",
    "--drop-direction",
    "server-to-client",
  ]);
  await delay(500);
  if (proxy.exitCode !== null || proxy.signalCode !== null) {
    throw new Error(
      `proxy exited before probe: code=${proxy.exitCode} signal=${proxy.signalCode}`,
    );
  }

  await runChecked("latency_probe", args["probe-exe"], [
    "--server",
    "127.0.0.1",
    "--port",
    String(proxyPort),
    "--frames",
    "240",
    "--jitter",
    "14",
    "--packets",
    "1000",
    "--require-clean",
  ]);
} finally {
  stopChild(proxy);
  stopChild(server);
}
