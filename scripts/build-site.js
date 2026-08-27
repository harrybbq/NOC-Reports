// Assembles the GitHub Pages payload into _site/.
//
// Usage: `npm run build:site` — or `node scripts/build-site.js`.
//
// The site is just standalone/ copied verbatim: no bundler, no transform, so
// what Pages serves is byte-for-byte what runs from `npm run serve`. Two
// additions are made on top of the copy:
//
//   .nojekyll    stops Pages running the payload through Jekyll, which would
//                otherwise drop any file or directory beginning with "_".
//   index.html   a landing page — but ONLY if standalone/ doesn't ship one.
//                When the UI slice lands as standalone/index.html, that real
//                app becomes the site root automatically and this generator
//                steps aside.

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SRC = path.join(ROOT, "standalone");
const OUT = path.join(ROOT, "_site");

await fs.rm(OUT, { recursive: true, force: true });
await fs.cp(SRC, OUT, { recursive: true });
await fs.writeFile(path.join(OUT, ".nojekyll"), "");

const indexPath = path.join(OUT, "index.html");
const hasRealIndex = await fs.access(indexPath).then(() => true, () => false);

if (hasRealIndex) {
  console.log("standalone/index.html present — using it as the site root.");
} else {
  await fs.writeFile(indexPath, landingPage());
  console.log("No standalone/index.html — wrote the generated landing page.");
}

const count = await countFiles(OUT);
console.log(`Built ${path.relative(ROOT, OUT)}/ — ${count} files.`);

async function countFiles(dir) {
  let n = 0;
  for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
    n += entry.isDirectory() ? await countFiles(path.join(dir, entry.name)) : 1;
  }
  return n;
}

// Hoisted so it can be called above its definition.
function landingPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>IPS Report Generator</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; margin: 0; padding: 40px 24px; background: #f7f8fa; color: #1a1a2e; line-height: 1.55; }
  main { max-width: 640px; margin: 0 auto; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  .lede { color: #5f6b7d; font-size: 14px; margin: 0 0 28px; }
  .card { display: block; background: #fff; border: 1px solid #e3e8f0; border-radius: 8px; padding: 16px 18px; margin-bottom: 12px; text-decoration: none; color: inherit; }
  .card:hover { border-color: #9db4d8; }
  .card h2 { font-size: 15px; margin: 0 0 4px; }
  .card p { font-size: 13px; color: #5f6b7d; margin: 0; }
  .pending { opacity: 0.6; }
  .note { font-size: 13px; color: #5f6b7d; border-top: 1px solid #e3e8f0; margin-top: 28px; padding-top: 16px; }
  code { background: #eef2fa; padding: 1px 6px; border-radius: 4px; font-size: 12px; }
</style>
</head>
<body>
<main>
  <h1>IPS Report Generator</h1>
  <p class="lede">Check Point IPS Blade and Fortinet FortiGate IPS parsing and validation.
  Everything runs in this browser tab — no upload, no server, no network calls.</p>

  <a class="card" href="tests.html">
    <h2>Test suite &rarr;</h2>
    <p>Runs the parser, CVE, defang and validator tests in the browser.</p>
  </a>

  <div class="card pending">
    <h2>Report UI</h2>
    <p>Not built yet. When it lands as <code>standalone/index.html</code> it replaces this page automatically.</p>
  </div>

  <p class="note">Served from GitHub Pages. This is the parser and validator slice only —
  it produces no workbook yet. See the repository README for what each module does
  and what is deliberately still missing.</p>
</main>
</body>
</html>
`;
}
