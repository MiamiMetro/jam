import dgram from "node:dgram";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

export function parseArgs(argv, options = {}) {
  const booleanFlags = new Set(options.booleanFlags ?? []);
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
      continue;
    }
    if (!arg.startsWith("--")) {
      throw new Error(`unknown argument: ${arg}`);
    }
    const name = arg.slice(2);
    if (booleanFlags.has(name)) {
      args[name] = true;
      continue;
    }
    if (i + 1 >= argv.length || argv[i + 1].startsWith("--")) {
      throw new Error(`missing value for ${arg}`);
    }
    args[name] = argv[++i];
  }
  return args;
}

export function requireArgs(args, names) {
  for (const name of names) {
    if (!args[name]) {
      throw new Error(`missing --${name}`);
    }
  }
}

export function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

export function reserveUdpPort() {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket("udp4");
    socket.once("error", reject);
    socket.bind(0, "127.0.0.1", () => {
      const port = socket.address().port;
      socket.close(() => resolve(port));
    });
  });
}

export function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function spawnLogged(name, command, args, logFile = "") {
  let stream = null;
  if (logFile) {
    ensureDir(path.dirname(logFile));
    stream = fs.createWriteStream(logFile, { flags: "a" });
    stream.write(`# ${name}\n`);
    stream.write(`# command: ${[command, ...args].join(" ")}\n\n`);
  }

  const child = spawn(command, args, {
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    process.stdout.write(`[${name}] ${chunk}`);
    stream?.write(chunk);
  });
  child.stderr.on("data", (chunk) => {
    process.stderr.write(`[${name}] ${chunk}`);
    stream?.write(chunk);
  });
  child.on("exit", (code, signal) => {
    stream?.end(`\n# exit: code=${code ?? ""} signal=${signal ?? ""}\n`);
  });
  child.on("error", (error) => {
    stream?.end(`\n# spawn error: ${error.message}\n`);
  });
  return child;
}

export function waitForOutput(child, pattern, timeoutMs, name) {
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

export function runLogged(name, command, args, logFile = "") {
  return new Promise((resolve) => {
    let output = "";
    const child = spawnLogged(name, command, args, logFile);
    child.stdout.on("data", (chunk) => {
      output += chunk;
    });
    child.stderr.on("data", (chunk) => {
      output += chunk;
    });
    child.on("exit", (code, signal) => {
      resolve({ code: code ?? (signal ? 1 : 0), signal, output });
    });
    child.on("error", (error) => {
      resolve({ code: 1, signal: null, output, error });
    });
  });
}

export function waitForExit(child) {
  return new Promise((resolve) => {
    if (!child || child.exitCode !== null || child.signalCode !== null) {
      resolve({
        code: child?.exitCode ?? (child?.signalCode ? 1 : 0),
        signal: child?.signalCode ?? null,
      });
      return;
    }
    child.once("exit", (code, signal) => {
      resolve({ code: code ?? (signal ? 1 : 0), signal });
    });
    child.once("error", (error) => {
      resolve({ code: 1, signal: null, error });
    });
  });
}

export async function stopChild(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) {
    return;
  }
  await new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(done, 5000);
    timer.unref?.();

    function done() {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      child.off("close", done);
      child.off("exit", done);
      child.off("error", done);
      resolve();
    }

    child.once("close", done);
    child.once("exit", done);
    child.once("error", done);
    child.kill();
  });
}

export function parseLatencyProbeOutput(text) {
  const metrics = {};
  for (const line of text.split(/\r?\n/)) {
    const e2e = line.match(
      /^e2e_latency_ms last\/avg\/max\/steady_max:\s*([-+0-9.eE]+)\/([-+0-9.eE]+)\/([-+0-9.eE]+)\/([-+0-9.eE]+)/,
    );
    if (e2e) {
      metrics.e2e_latency_last_ms = Number(e2e[1]);
      metrics.e2e_latency_avg_ms = Number(e2e[2]);
      metrics.e2e_latency_max_ms = Number(e2e[3]);
      metrics.e2e_latency_steady_max_ms = Number(e2e[4]);
      continue;
    }

    const scalar = line.match(/^([a-zA-Z0-9_]+):\s*([-+0-9.eE]+)/);
    if (scalar) {
      metrics[scalar[1]] = Number(scalar[2]);
    }
  }
  return metrics;
}

export function assertBudget(condition, message, failures) {
  if (!condition) {
    failures.push(message);
  }
}

export function writeJson(file, value) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}
