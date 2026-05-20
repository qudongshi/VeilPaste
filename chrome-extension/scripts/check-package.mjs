import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const extensionRoot = path.resolve(import.meta.dirname, "..");
const zipPath = process.argv[2] ? path.resolve(process.argv[2]) : null;
const errors = [];

if (zipPath) {
  checkZip(zipPath);
} else {
  checkTree(extensionRoot);
}

for (const requiredPath of [
  "manifest.json",
  "help.html",
  "dist/background.js",
  "dist/content.js",
  "dist/detector.js",
  "dist/options.js",
  "dist/panel.js",
  "icons/veilpaste_16.png",
  "icons/veilpaste_32.png",
  "icons/veilpaste_48.png",
  "icons/veilpaste_128.png",
]) {
  assertExists(path.join(extensionRoot, requiredPath), requiredPath);
}

if (errors.length > 0) {
  console.error(errors.join("\n"));
  process.exit(1);
}

function checkTree(root) {
  for (const entry of walk(root)) {
    const relativePath = path.relative(root, entry);
    if (isDisallowedPackageEntry(relativePath)) {
      errors.push(`package artifact must be removed: ${relativePath}`);
    }
  }
}

function checkZip(filePath) {
  let entries;
  try {
    entries = execFileSync("zipinfo", ["-1", filePath], { encoding: "utf8" })
      .split("\n")
      .filter(Boolean);
  } catch (error) {
    errors.push(`could not inspect zip package: ${error.message}`);
    return;
  }

  for (const entry of entries) {
    if (isDisallowedPackageEntry(entry)) {
      errors.push(`zip package contains disallowed artifact: ${entry}`);
    }
  }
}

function* walk(dir) {
  for (const dirent of fs.readdirSync(dir, { withFileTypes: true })) {
    if (dirent.name === "node_modules") {
      continue;
    }

    const entry = path.join(dir, dirent.name);
    if (dirent.isDirectory()) {
      yield* walk(entry);
    } else {
      yield entry;
    }
  }
}

function isDisallowedPackageEntry(entry) {
  const normalized = entry.replaceAll("\\", "/");
  const basename = path.posix.basename(normalized);
  return basename === ".DS_Store" || normalized.startsWith("__MACOSX/") || basename.endsWith(".profraw");
}

function assertExists(filePath, label) {
  if (!fs.existsSync(filePath)) {
    errors.push(`required package file missing: ${label}`);
  }
}
