// Node harness for the same test suite that runs in the browser.
//
// Usage: `node node-run.js` from the standalone/ directory. Exits with
// status 1 on any failure.
//
// The test files call `fetch("fixtures/...")` to load CSV fixtures; in Node
// we stub fetch to read from disk. Every other API used by the tests is
// pure JS.

import fs from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const HERE = path.dirname(new URL(import.meta.url).pathname);

globalThis.fetch = async (spec) => {
  const target = path.resolve(HERE, "tests", spec);
  try {
    const text = await fs.readFile(target, "utf8");
    return { ok: true, status: 200, text: async () => text };
  } catch (e) {
    return { ok: false, status: 404, text: async () => "" };
  }
};

await import("./tests/cve-defang.test.js");
await import("./tests/parse-checkpoint.test.js");
await import("./tests/parse-fortinet.test.js");
await import("./tests/validate.test.js");

const { runAll } = await import("./tests/runner.js");
const result = await runAll();
process.exit(result.fail === 0 ? 0 : 1);
