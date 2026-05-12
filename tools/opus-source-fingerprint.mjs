import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const skippedDirectories = new Set([
  ".agents",
  ".cache",
  ".claude",
  ".cursor",
  ".git",
  ".idea",
  ".vscode",
  ".vscode-test",
  "build",
  "hls",
  "html",
  "node_modules",
  "notes",
  "out",
  "validation",
  "validation_logs",
]);

const sourceExtensions = new Set([".cpp", ".h", ".hpp", ".json", ".md", ".mjs"]);

function toRepoPath(repoRoot, fullPath) {
  return path.relative(repoRoot, fullPath).split(path.sep).join("/");
}

function includeSourceFile(name) {
  if (name === "skills-lock.json") return false;
  return name === ".gitignore" || name === "CMakeLists.txt" || sourceExtensions.has(path.extname(name));
}

function walkSourceFiles(repoRoot, dir, files) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (skippedDirectories.has(entry.name) || entry.name.startsWith("cmake-build-")) continue;
      walkSourceFiles(repoRoot, path.join(dir, entry.name), files);
      continue;
    }
    if (entry.isFile() && includeSourceFile(entry.name)) {
      files.push(toRepoPath(repoRoot, path.join(dir, entry.name)));
    }
  }
}

export function sourceFingerprintFileList(repoRoot) {
  const files = [];
  walkSourceFiles(repoRoot, repoRoot, files);
  return files.sort((a, b) => a.localeCompare(b));
}

export function sourceFingerprint(repoRoot) {
  const hash = crypto.createHash("sha256");
  for (const file of sourceFingerprintFileList(repoRoot)) {
    const full = path.resolve(repoRoot, file);
    hash.update(file);
    hash.update("\0");
    if (fs.existsSync(full)) {
      const normalizedText = fs.readFileSync(full, "utf8").replace(/\r\n?/g, "\n");
      hash.update(normalizedText);
    }
    else hash.update("<missing>");
    hash.update("\0");
  }
  return hash.digest("hex");
}

const modulePath = fileURLToPath(import.meta.url);
if (process.argv[1] && path.resolve(process.argv[1]) === modulePath) {
  if (process.argv[2] === "--help" || process.argv[2] === "-h") {
    console.log("usage: node tools/opus-source-fingerprint.mjs [repo-root]");
    process.exit(0);
  }
  const repoRoot = process.argv[2] ? path.resolve(process.argv[2]) : path.resolve(path.dirname(modulePath), "..");
  console.log(`Source SHA256: ${sourceFingerprint(repoRoot)}`);
  console.log(`Source files: ${sourceFingerprintFileList(repoRoot).length}`);
}
