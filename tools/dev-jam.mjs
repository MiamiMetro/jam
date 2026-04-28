#!/usr/bin/env node

import crypto from "node:crypto";
import dgram from "node:dgram";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Edit these defaults for your local dev loop.
const DEV = {
  serverHost: "127.0.0.1",
  port: process.env.JAM_DEV_PORT ?? "9999",
  serverId: "local-dev",
  secret: "dev-secret",
  codec: "opus",
  frames: "120",
  ttlMs: 10 * 60 * 1000,
  spamPackets: 1000,
  spamIntervalMs: 1,
  serverExe: "build/Debug/server.exe",
  clientExe: "build/Debug/client.exe",
  clients: {
    a: { room: "room-a", user: "user-a1", displayName: "User A1" },
    b: { room: "room-a", user: "user-a2", displayName: "User A2" },
    c: { room: "room-b", user: "user-b1", displayName: "User B1" },
  },
};

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function abs(relativePath) {
  return path.resolve(repoRoot, relativePath);
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

function run(command, args) {
  console.log([command, ...args].join(" "));
  const child = spawn(command, args, {
    cwd: repoRoot,
    stdio: "inherit",
    windowsHide: false,
  });
  child.on("exit", (code, signal) => {
    if (signal) process.exit(1);
    process.exit(code ?? 0);
  });
}

function usage() {
  console.log(
    [
      "usage:",
      "  node tools/dev-jam.mjs server",
      "  node tools/dev-jam.mjs client a",
      "  node tools/dev-jam.mjs client b",
      "  node tools/dev-jam.mjs client c",
      "  node tools/dev-jam.mjs spam",
      "",
      "defaults live at the top of tools/dev-jam.mjs",
      "default rooms: a+b in room-a, c in room-b",
    ].join("\n"),
  );
}

const [command, id] = process.argv.slice(2);

if (command === "server") {
  run(abs(DEV.serverExe), [
    "--port",
    DEV.port,
    "--server-id",
    DEV.serverId,
    "--join-secret",
    DEV.secret,
  ]);
} else if (command === "client") {
  const client = DEV.clients[id];
  if (!client) {
    console.error(`unknown client '${id ?? ""}'`);
    usage();
    process.exit(2);
  }

  run(abs(DEV.clientExe), [
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
    DEV.codec,
    "--frames",
    DEV.frames,
  ]);
} else if (command === "spam") {
  const socket = dgram.createSocket("udp4");
  const packet = Buffer.alloc(10);
  packet.writeUInt32LE(0x41554449, 0); // AUDIO_MAGIC
  packet.writeUInt32LE(0, 4); // sender_id, ignored by the server
  packet.writeUInt16LE(0, 8); // encoded_bytes

  let sent = 0;
  const sendOne = () => {
    socket.send(packet, Number(DEV.port), DEV.serverHost, (error) => {
      if (error) {
        console.error(error.message);
        socket.close();
        process.exit(1);
      }
    });

    sent += 1;
    if (sent >= DEV.spamPackets) {
      console.log(`sent ${sent} unjoined audio packets to ${DEV.serverHost}:${DEV.port}`);
      socket.close();
      return;
    }
    setTimeout(sendOne, DEV.spamIntervalMs);
  };

  sendOne();
} else {
  usage();
  process.exit(command ? 2 : 0);
}
