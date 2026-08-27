// Dependency-free static server.
//
// Usage (from the repo root):
//   npm run serve              serves standalone/ on http://localhost:8000
//   npm run serve -- 9000      same, on port 9000
//   node scripts/serve.js --root _site --port 8080
//
// Also exports createStaticServer() so scripts/browser-test.js can serve a
// build without shelling out.
//
// The browser test page and the eventual UI are ES modules, which browsers
// refuse to load over file://. Serving them over HTTP is the whole job here;
// there is no build step and nothing is installed.

import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

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

export function createStaticServer(rootDir) {
  const root = path.resolve(rootDir);
  return http.createServer(async (req, res) => {
    let pathname;
    try {
      pathname = decodeURIComponent(new URL(req.url, "http://localhost").pathname);
    } catch {
      res.writeHead(400).end("Bad request");
      return;
    }
    if (pathname.endsWith("/")) pathname += "index.html";

    // Resolve inside root only — a request must never escape the served tree.
    const target = path.resolve(root, "." + pathname);
    if (target !== root && !target.startsWith(root + path.sep)) {
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
}

// Run directly (not imported)?
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const flag = (name) => { const i = args.indexOf(name); return i === -1 ? null : args[i + 1]; };
  const positionalPort = args.find((a) => /^\d+$/.test(a));

  const root = path.resolve(REPO, flag("--root") || "standalone");
  const port = Number(flag("--port") || positionalPort || process.env.PORT || 8000);

  createStaticServer(root).listen(port, () => {
    console.log(`Serving ${root}`);
    console.log(`  tests:  http://localhost:${port}/tests.html`);
  });
}
