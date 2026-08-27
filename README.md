# NOC-Reports

NOC reporting tooling. Currently hosts the **IPS Report Generator** (`standalone/`) —
the parser and validator slice for Check Point IPS Blade and Fortinet FortiGate IPS
exports. Pure JavaScript, no build step, no runtime dependencies, no CDN.

## Layout

```
standalone/     the IPS Report Generator drop (see standalone/README.md)
scripts/        repo tooling — currently a dependency-free static server
```

## Running it

Everything runs from the repo root with Node 18+. There is nothing to install —
`npm install` is not required, and there are no dependencies to fetch.

**Tests (Node):**

```
npm test
```

Runs the full suite (`standalone/node-run.js`) and exits non-zero on any failure,
so it drops straight into CI.

**Tests (browser)** — matches the runtime the app will actually use:

```
npm run serve          # serves standalone/ on http://localhost:8000
```

then open <http://localhost:8000/tests.html>. The page must be served over HTTP;
opening it via `file://` blocks ES-module imports in every modern browser.

Pick a different port with `npm run serve -- 9000` or `PORT=9000 npm run serve`.

The equivalents still work from inside `standalone/` (`node node-run.js`,
`python -m http.server`) — the root scripts just save the `cd`.

## Where to read next

`standalone/README.md` covers what the parsers and validator do, the common event
shape every vendor parser returns, what the validator blocks versus warns on, and
what is deliberately not built yet.
