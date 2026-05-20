import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "../..");
const contract = readJson("fixtures/shared-contract/rules.json");
const vectors = readJson("fixtures/shared-vectors/p0-secrets.json");

const errors = [];
assertUnique(contract.rules, "kind");
assertUnique(contract.rules, "rust_kind");
assertUnique(contract.rules, "placeholder_prefix");

const prefixes = new Set(contract.rules.map((rule) => rule.placeholder_prefix));
for (const vector of vectors) {
  for (const expected of vector.expect_contains ?? []) {
    for (const placeholder of expected.matchAll(/\[([A-Z0-9_]+)_\d+\]/g)) {
      const prefix = placeholder[1];
      if (!prefixes.has(prefix)) {
        errors.push(`${vector.name}: missing contract prefix ${prefix}`);
      }
    }
  }
}

if (errors.length > 0) {
  console.error(errors.join("\n"));
  process.exit(1);
}

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(root, relativePath), "utf8"));
}

function assertUnique(items, field) {
  const seen = new Set();
  for (const item of items) {
    if (seen.has(item[field])) {
      errors.push(`duplicate ${field}: ${item[field]}`);
    }
    seen.add(item[field]);
  }
}
