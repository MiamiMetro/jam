#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { sourceFingerprint, sourceFingerprintFileList } from "./opus-source-fingerprint.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const minValidationTtlMs = 3 * 60 * 60 * 1000;

const defaults = {
  serverHost: "",
  port: "9999",
  serverId: "local-dev",
  secret: "",
  room: "opus-validation-room",
  longRoom: "opus-validation-long-room",
  ttlMs: String(4 * 60 * 60 * 1000),
  outDir: "validation",
  manifest: "validation/opus-external-validation.json",
  windowsSmoke: "latest",
  macSmoke: "latest",
  windowsClient: ".\\build\\Debug\\client.exe",
  windowsServer: ".\\build\\Debug\\server.exe",
  macClient: "./build/client",
  macServer: "./build/server",
  write: "",
  allowLoopback: false,
};

function usage() {
  console.log(
    [
      "usage:",
      "  node tools/opus-external-commands.mjs --secret <secret> --server-host <host-or-ip>",
      "",
      "optional:",
      "  --port 9999 --server-id local-dev --room opus-validation-room",
      "  --long-room opus-validation-long-room --ttl-ms 14400000",
      "  --out-dir validation --manifest validation/opus-external-validation.json",
      "  --windows-smoke latest --mac-smoke latest",
      "  --windows-client <path> --windows-server <path>",
      "  --mac-client <path> --mac-server <path>",
      "  --write <markdown-file>",
      "  --allow-loopback   only for local command-shape testing, not external proof",
      "",
      "Prints copy/paste commands for external Windows/macOS Opus 120 evidence capture.",
    ].join("\n"),
  );
}

function parseArgs(argv) {
  const options = { ...defaults };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1];
    if (arg === "--server-host" && next) options.serverHost = argv[++i];
    else if (arg === "--port" && next) options.port = argv[++i];
    else if (arg === "--server-id" && next) options.serverId = argv[++i];
    else if (arg === "--secret" && next) options.secret = argv[++i];
    else if (arg === "--room" && next) options.room = argv[++i];
    else if (arg === "--long-room" && next) options.longRoom = argv[++i];
    else if (arg === "--ttl-ms" && next) options.ttlMs = argv[++i];
    else if (arg === "--out-dir" && next) options.outDir = argv[++i];
    else if (arg === "--manifest" && next) options.manifest = argv[++i];
    else if (arg === "--windows-smoke" && next) options.windowsSmoke = argv[++i];
    else if (arg === "--mac-smoke" && next) options.macSmoke = argv[++i];
    else if (arg === "--windows-client" && next) options.windowsClient = argv[++i];
    else if (arg === "--windows-server" && next) options.windowsServer = argv[++i];
    else if (arg === "--mac-client" && next) options.macClient = argv[++i];
    else if (arg === "--mac-server" && next) options.macServer = argv[++i];
    else if (arg === "--write" && next) options.write = argv[++i];
    else if (arg === "--allow-loopback") options.allowLoopback = true;
    else if (arg === "--help" || arg === "-h") {
      usage();
      process.exit(0);
    } else {
      throw new Error(`unknown option: ${arg}`);
    }
  }
  return options;
}

function repoRelativePath(value) {
  const full = path.isAbsolute(value) ? value : path.resolve(repoRoot, value);
  const relative = path.relative(repoRoot, full);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) return "";
  return relative.split(path.sep).join("/");
}

function ignoredRepoPathIssue(value, description = "external command output path") {
  const relative = repoRelativePath(value);
  if (!relative) return "";
  const result = spawnSync("git", ["check-ignore", relative], {
    cwd: repoRoot,
    encoding: "utf8",
    timeout: 30000,
    windowsHide: true,
  });
  if ((result.status ?? 1) === 0) return "";
  return `${description} inside repo must be ignored generated evidence: ${relative}`;
}

function isLoopbackOrUnroutableHost(value) {
  const normalized = String(value || "").trim().toLowerCase();
  let unbracketed = normalized;
  if (normalized.startsWith("[")) {
    const closeBracket = normalized.indexOf("]");
    if (closeBracket > 0) unbracketed = normalized.slice(1, closeBracket);
  }
  const hostname = unbracketed.split(":")[0];
  const fullIpv6Loopback = unbracketed === "0:0:0:0:0:0:0:1" || unbracketed.startsWith("0:0:0:0:0:0:0:1:");
  const fullIpv6Unspecified = unbracketed === "0:0:0:0:0:0:0:0" || unbracketed.startsWith("0:0:0:0:0:0:0:0:");
  return (
    hostname === "localhost" ||
    unbracketed === "::1" ||
    fullIpv6Loopback ||
    unbracketed === "::" ||
    fullIpv6Unspecified ||
    hostname === "0.0.0.0" ||
    hostname.startsWith("127.") ||
    unbracketed.startsWith("::ffff:127.")
  );
}

function validateTtlMs(value) {
  const text = String(value || "").trim();
  if (!/^\d+$/.test(text)) {
    throw new Error("--ttl-ms must be an integer number of milliseconds");
  }
  const ttl = Number(text);
  if (!Number.isSafeInteger(ttl) || ttl <= 0) {
    throw new Error("--ttl-ms must be a positive safe integer");
  }
  if (ttl < minValidationTtlMs) {
    throw new Error(`--ttl-ms must be at least ${minValidationTtlMs} ms for external validation`);
  }
  return ttl;
}

function shellQuote(value, shell) {
  if (/^[A-Za-z0-9_./:=+\\-]+$/.test(value)) return value;
  if (shell === "powershell") return `"${value.replaceAll("`", "``").replaceAll('"', '`"')}"`;
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

function command(parts, shell) {
  return parts.map((part) => shellQuote(String(part), shell)).join(" ");
}

function joinToken(options, room, user) {
  const expiresAtMs = options.expiresAtMs ?? Date.now() + Number(options.ttlMs);
  const nonce = crypto.randomBytes(16).toString("hex");
  const role = "performer";
  const payload = ["v1", expiresAtMs, options.serverId, room, user, role, nonce].join("|");
  const signature = crypto.createHmac("sha256", options.secret).update(payload).digest("hex");
  return ["v1", expiresAtMs, options.serverId, room, user, role, nonce, signature].join(".");
}

function logPath(options, name) {
  return path.posix.join(options.outDir.replaceAll("\\", "/"), name);
}

function sessionRoom(options, suffix) {
  return `${options.room}-${suffix}`;
}

function clientCommand(options, platform, room, user, displayName, logFile) {
  const shell = platform === "windows" ? "powershell" : "posix";
  const client = platform === "windows" ? options.windowsClient : options.macClient;
  return command(
    [
      client,
      "--server",
      options.serverHost,
      "--port",
      options.port,
      "--room",
      room,
      "--room-handle",
      room,
      "--user-id",
      user,
      "--display-name",
      displayName,
      "--join-token",
      joinToken(options, room, user),
      "--codec",
      "opus",
      "--frames",
      "120",
      "--jitter",
      "8",
      "--auto-jitter",
      "--log-file",
      logFile,
    ],
    shell,
  );
}

function serverCommand(options, platform, logFile) {
  const shell = platform === "windows" ? "powershell" : "posix";
  const server = platform === "windows" ? options.windowsServer : options.macServer;
  return command(
    [
      server,
      "--port",
      options.port,
      "--server-id",
      options.serverId,
      "--join-secret",
      options.secret,
      "--log-file",
      logFile,
    ],
    shell,
  );
}

function render(options) {
  const generatedAtMs = options.generatedAtMs ?? Date.now();
  const expiresAtMs = options.expiresAtMs ?? generatedAtMs + Number(options.ttlMs);
  options.generatedAtMs = generatedAtMs;
  options.expiresAtMs = expiresAtMs;
  const winToMacRoom = sessionRoom(options, "win-to-mac");
  const macToWinRoom = sessionRoom(options, "mac-to-win");
  const winToMac = {
    server: logPath(options, "win-to-mac-server.log"),
    windows: logPath(options, "win-to-mac-windows-client.log"),
    macos: logPath(options, "win-to-mac-macos-client.log"),
  };
  const macToWin = {
    server: logPath(options, "mac-to-win-server.log"),
    windows: logPath(options, "mac-to-win-windows-client.log"),
    macos: logPath(options, "mac-to-win-macos-client.log"),
  };
  const long = {
    server: logPath(options, "server-long.log"),
    windows: logPath(options, "windows-client-long.log"),
    macos: logPath(options, "macos-client-long.log"),
  };

  return [
    "# External Opus 120 Evidence Commands",
    "",
    "Run these after building the same branch on Windows and macOS.",
    "",
    `Validation token TTL: ${Number.parseInt(options.ttlMs, 10)} ms. This is only for this external validation helper; production join-token TTL is separate.`,
    `Generated at (UTC): ${new Date(generatedAtMs).toISOString()}`,
    `Validation tokens expire at (UTC): ${new Date(expiresAtMs).toISOString()}`,
    "Regenerate this command sheet before running validation if the expiry is too close for setup, both 5-minute checks, and the long session.",
    `Source SHA256: ${sourceFingerprint(repoRoot)}`,
    `Source files: ${sourceFingerprintFileList(repoRoot).length}`,
    "",
    "## Preflight On Checker Machine",
    "",
    "Run this on the machine that will collect logs and run the manifest checker before starting long validation:",
    "",
    "```bash",
    "node tools/opus-completion-audit.mjs --local-only",
    "node tools/opus-source-fingerprint.mjs",
    "git check-ignore validation/opus-external-commands.md validation/opus-external-validation.json validation/validation-summary.md validation_logs/legacy-evidence.json",
    "```",
    "",
    "The local-only audit must pass, `node tools/opus-source-fingerprint.mjs` must print the same `Source SHA256` shown above, and `git check-ignore` must print each generated validation path so tokens, manifests, summaries, and logs are not staged as source.",
    "",
    "## Machine Smoke",
    "",
    "Windows:",
    "",
    "```powershell",
    "node tools/opus-validation.mjs smoke",
    "```",
    "",
    "macOS:",
    "",
    "```bash",
    "node tools/opus-validation.mjs smoke",
    "```",
    "",
    "## Prepare Evidence Directory",
    "",
    "Run this before starting SFU/client commands on each machine that writes validation logs.",
    "",
    "Windows:",
    "",
    "```powershell",
    command(["New-Item", "-ItemType", "Directory", "-Force", "-Path", options.outDir], "powershell"),
    "```",
    "",
    "macOS:",
    "",
    "```bash",
    command(["mkdir", "-p", options.outDir], "posix"),
    "```",
    "",
    "## Windows To macOS Session",
    "",
    "Start SFU on the host machine, choosing the Windows or macOS command that matches where the SFU runs.",
    "For this direction, make Windows the active talker/source and judge the received audio on macOS for at least 5 minutes. Note that direction in the manifest subjective field.",
    "",
    "Windows SFU:",
    "",
    "```powershell",
    serverCommand(options, "windows", winToMac.server),
    "```",
    "",
    "macOS SFU:",
    "",
    "```bash",
    serverCommand(options, "macos", winToMac.server),
    "```",
    "",
    "Windows client:",
    "",
    "```powershell",
    clientCommand(options, "windows", winToMacRoom, "windows-user", "Windows User", winToMac.windows),
    "```",
    "",
    "macOS client:",
    "",
    "```bash",
    clientCommand(options, "macos", winToMacRoom, "macos-user", "macOS User", winToMac.macos),
    "```",
    "",
    "## macOS To Windows Session",
    "",
    "Restart or relaunch the SFU with a fresh log file.",
    "For this direction, make macOS the active talker/source and judge the received audio on Windows for at least 5 minutes. Note that direction in the manifest subjective field.",
    "",
    "Windows SFU:",
    "",
    "```powershell",
    serverCommand(options, "windows", macToWin.server),
    "```",
    "",
    "macOS SFU:",
    "",
    "```bash",
    serverCommand(options, "macos", macToWin.server),
    "```",
    "",
    "Windows client:",
    "",
    "```powershell",
    clientCommand(options, "windows", macToWinRoom, "windows-user", "Windows User", macToWin.windows),
    "```",
    "",
    "macOS client:",
    "",
    "```bash",
    clientCommand(options, "macos", macToWinRoom, "macos-user", "macOS User", macToWin.macos),
    "```",
    "",
    "## Long Session",
    "",
    "Run 30-60 minutes with both clients active. Exercise both directions during the run and note any flicker, PLC, or drift symptoms in the manifest subjective field.",
    "",
    "Windows SFU:",
    "",
    "```powershell",
    serverCommand(options, "windows", long.server),
    "```",
    "",
    "macOS SFU:",
    "",
    "```bash",
    serverCommand(options, "macos", long.server),
    "```",
    "",
    "Windows client:",
    "",
    "```powershell",
    clientCommand(options, "windows", options.longRoom, "windows-user-long", "Windows User", long.windows),
    "```",
    "",
    "macOS client:",
    "",
    "```bash",
    clientCommand(options, "macos", options.longRoom, "macos-user-long", "macOS User", long.macos),
    "```",
    "",
    "## Collect Logs Onto One Machine",
    "",
    "Before summarizing or initializing the manifest, copy every generated log and both smoke report directories onto the same machine running the checker.",
    "",
    "Expected final paths relative to the repo root:",
    "",
    "```text",
    `windows smoke report: ${options.windowsSmoke}`,
    `macOS smoke report: ${options.macSmoke}`,
    `room: ${winToMacRoom}`,
    winToMac.windows,
    winToMac.macos,
    winToMac.server,
    `room: ${macToWinRoom}`,
    macToWin.windows,
    macToWin.macos,
    macToWin.server,
    `room: ${options.longRoom}`,
    long.windows,
    long.macos,
    long.server,
    "```",
    "",
    "Preserve the `startup-default-client.log` file beside each smoke `report.md`; the checker reads those neighboring logs.",
    "The manifest init command uses `latest` by default, which auto-selects the newest current-source Windows and macOS smoke reports from `build/opus-validation`.",
    "",
    "## Summarize And Check",
    "",
    "```bash",
    command(
      [
        "node",
        "tools/opus-log-summary.mjs",
        "--out",
        logPath(options, "validation-summary.md"),
        winToMac.windows,
        winToMac.macos,
        winToMac.server,
        macToWin.windows,
        macToWin.macos,
        macToWin.server,
        long.windows,
        long.macos,
        long.server,
      ],
      "posix",
    ),
    "```",
    "",
    "The summary output path must be ignored generated evidence; `opus-log-summary` rejects source-controlled repo-local output paths.",
    "",
    "```bash",
    command(
      [
        "node",
        "tools/opus-external-evidence-check.mjs",
        "--init",
        options.manifest,
        "--windows-smoke",
        options.windowsSmoke,
        "--mac-smoke",
        options.macSmoke,
        "--win-to-mac-logs",
        [winToMac.windows, winToMac.macos, winToMac.server].join(","),
        "--win-to-mac-room",
        winToMacRoom,
        "--mac-to-win-logs",
        [macToWin.windows, macToWin.macos, macToWin.server].join(","),
        "--mac-to-win-room",
        macToWinRoom,
        "--long-logs",
        [long.windows, long.macos, long.server].join(","),
        "--long-room",
        options.longRoom,
      ],
      "posix",
    ),
    "```",
    "",
    "The manifest output path must be ignored generated evidence; the preflight `git check-ignore` command above verifies the default path.",
    "",
    "Edit the manifest network and subjective notes, replacing placeholders such as `lan-or-tunnel` and `clear / flicker / robotic / dropout notes`; the checker rejects placeholders. Then run:",
    "",
    "```bash",
    command(["node", "tools/opus-external-evidence-check.mjs", options.manifest], "posix"),
    "```",
    "",
    "Then run the final promotion gate:",
    "",
    "```bash",
    command(["node", "tools/opus-acceptance.mjs", "--external-manifest", options.manifest], "posix"),
    "```",
    "",
    "The final promotion gate runs the external checker in strict mode, so review warnings still block acceptance.",
    "",
  ].join("\n");
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  if (!options.secret) {
    usage();
    throw new Error("--secret is required so generated client commands use signed join tokens");
  }
  if (!options.serverHost) {
    usage();
    throw new Error("--server-host is required so generated client commands target the actual SFU host");
  }
  if (!options.allowLoopback && isLoopbackOrUnroutableHost(options.serverHost)) {
    throw new Error("--server-host must be reachable from both Windows and macOS; loopback/unroutable hosts require --allow-loopback and do not count as external proof");
  }
  options.ttlMs = String(validateTtlMs(options.ttlMs));
  options.generatedAtMs = Date.now();
  options.expiresAtMs = options.generatedAtMs + Number(options.ttlMs);
  const outDirIssue = ignoredRepoPathIssue(
    path.join(options.outDir, "validation-summary.md"),
    "external validation output path",
  );
  if (outDirIssue) {
    throw new Error(outDirIssue);
  }
  const manifestIssue = ignoredRepoPathIssue(options.manifest, "external manifest path");
  if (manifestIssue) {
    throw new Error(manifestIssue);
  }

  const output = render(options);
  if (options.write) {
    const writePathIssue = ignoredRepoPathIssue(options.write);
    if (writePathIssue) {
      throw new Error(writePathIssue);
    }
    const outFile = path.isAbsolute(options.write) ? options.write : path.resolve(repoRoot, options.write);
    fs.mkdirSync(path.dirname(outFile), { recursive: true });
    fs.writeFileSync(outFile, output, "utf8");
    console.log(`wrote ${path.relative(repoRoot, outFile).split(path.sep).join("/")}`);
  } else {
    console.log(output);
  }
}

try {
  main();
} catch (error) {
  console.error(error.message);
  process.exit(2);
}
