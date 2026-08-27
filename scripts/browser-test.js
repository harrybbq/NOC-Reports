// Runs standalone/tests.html in a real headless browser and fails the process
// if any assertion failed.
//
// Usage: `npm run test:browser` — or `node scripts/browser-test.js`.
//
// Why this exists: the Node harness (standalone/node-run.js) stubs fetch, so
// it cannot catch problems that only appear under real browser URL resolution
// or real ES-module loading. The app ships as a browser app; this checks the
// browser path end to end.
//
// No Playwright, no npm install: it serves the built _site/ from Node and
// drives whatever Chrome/Chromium is already on the machine. Set CHROME_PATH
// to point at a specific binary.

import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createStaticServer } from "./serve.js";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SITE = path.join(REPO, "_site");

const CANDIDATES = [
  process.env.CHROME_PATH,
  "/opt/pw-browsers/chromium-1194/chrome-linux/chrome",
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
].filter(Boolean);

const chrome = CANDIDATES.find((p) => { try { return fs.existsSync(p); } catch { return false; } });
if (!chrome) {
  console.error("No Chrome/Chromium found. Set CHROME_PATH to a browser binary.");
  console.error("Looked in:\n  " + CANDIDATES.join("\n  "));
  process.exit(1);
}
if (!fs.existsSync(path.join(SITE, "tests.html"))) {
  console.error(`No _site/tests.html — run \`npm run build:site\` first.`);
  process.exit(1);
}

const server = createStaticServer(SITE);
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const url = `http://127.0.0.1:${server.address().port}/tests.html`;
console.log(`Browser: ${chrome}`);
console.log(`Loading: ${url}`);

const dom = await dumpDom(chrome, url);
server.close();

// The runner writes "<n> passed, <n> failed, <n> total" into .summary.
const m = dom.match(/(\d+) passed, (\d+) failed, (\d+) total/);
if (!m) {
  console.error("Could not find the test summary in the rendered page.");
  console.error("The page probably failed to load or a module threw. DOM follows:\n");
  console.error(dom.slice(0, 4000));
  process.exit(1);
}

const [, pass, fail, total] = m.map(Number);
if (fail === 0 && pass === total && total > 0) {
  console.log(`\n${pass} passed, ${fail} failed, ${total} total`);
  process.exit(0);
}

// Surface each failing test name and message rather than the whole DOM.
for (const f of dom.matchAll(/<div class="fail-name">([^<]*)<\/div><pre class="fail-msg">([\s\S]*?)<\/pre>/g)) {
  const name = decodeEntities(f[1]).replace(/^✗\s*/, "");
  console.error(`\n✗ ${name}\n  ${decodeEntities(f[2]).replace(/\n/g, "\n  ")}`);
}
console.error(`\n${pass} passed, ${fail} failed, ${total} total`);
process.exit(1);

function dumpDom(bin, target) {
  // --virtual-time-budget lets the module imports, fetches and assertions
  // finish before the DOM is dumped; it is virtual time, not a wall-clock wait.
  const args = [
    "--headless", "--disable-gpu", "--no-sandbox", "--no-first-run",
    "--disable-dev-shm-usage", "--virtual-time-budget=30000", "--dump-dom", target,
  ];
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    child.stdout.on("data", (d) => { out += d; });
    child.stderr.on("data", (d) => { err += d; });
    const killer = setTimeout(() => child.kill("SIGKILL"), 120_000);
    child.on("error", (e) => { clearTimeout(killer); reject(e); });
    child.on("close", (code) => {
      clearTimeout(killer);
      if (code !== 0 && !out) reject(new Error(`Browser exited ${code}:\n${err}`));
      else resolve(out);
    });
  });
}

function decodeEntities(s) {
  return s.replace(/&(amp|lt|gt|quot|#39);/g, (_, e) =>
    ({ amp: "&", lt: "<", gt: ">", quot: '"', "#39": "'" }[e]));
}
