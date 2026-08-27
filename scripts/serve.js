// Dependency-free static server for the standalone/ tree.
//
// Usage (from the repo root): `npm run serve` — or `node scripts/serve.js`.
// Optional: PORT env var, or `node scripts/serve.js 9000`.
//
// The browser test page and the eventual UI are ES modules, which browsers
// refuse to load over file://. Serving them over HTTP is the whole job here;
// there is no build step and nothing is installed.

import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "standalone");
const PORT = Number(process.argv[2] || process.env.PORT || 8000);

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".csv": "text/csv; charset=utf-8",
  ".md": "text/plain; charset=utf-8",
  ".svg": "image/svg+xml",
};

const server = http.createServer(async (req, res) => {
  let pathname;
  try {
    pathname = decodeURIComponent(new URL(req.url, "http://localhost").pathname);
  } catch {
    res.writeHead(400).end("Bad request");
    return;
  }
  if (pathname.endsWith("/")) pathname += "index.html";

  // Resolve inside ROOT only — a request must never escape the served tree.
  const target = path.resolve(ROOT, "." + pathname);
  if (target !== ROOT && !target.startsWith(ROOT + path.sep)) {
    res.writeHead(403).end("Forbidden");
    return;
  }

  try {
    const body = await fs.readFile(target);
    res.writeHead(200, {
      "Content-Type": TYPES[path.extname(target).toLowerCase()] || "application/octet-stream",
      "Cache-Control": "no-store",
    });
    res.end(body);
  } catch (e) {
    if (e.code === "ENOENT" || e.code === "EISDIR") res.writeHead(404).end("Not found");
    else { res.writeHead(500).end("Server error"); console.error(e); }
  }
});

server.listen(PORT, () => {
  console.log(`Serving ${ROOT}`);
  console.log(`  tests:  http://localhost:${PORT}/tests.html`);
});
