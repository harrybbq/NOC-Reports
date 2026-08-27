# NOC-Reports

NOC reporting tooling. Currently hosts the **IPS Report Generator** (`standalone/`) —
the parser and validator slice for Check Point IPS Blade and Fortinet FortiGate IPS
exports. Pure JavaScript, no build step, no runtime dependencies, no CDN.

## Layout

```
standalone/         the IPS Report Generator (see standalone/README.md)
scripts/            repo tooling — static server, site build, browser test driver
.github/workflows/  CI (tests) and the GitHub Pages deploy
```

## Use it without installing anything

The app is deployed to GitHub Pages on every push to `main`:

**<https://harrybbq.github.io/NOC-Reports/>**

Open it in any browser — nothing to install, nothing to run locally. Parsing
happens entirely in the browser tab: the code makes no network calls and no
file you open is ever uploaded anywhere. Note the repository is public, so the
page and its source are publicly reachable; the synthetic fixtures are the only
data in the repo.

Tests are at [`/tests.html`](https://harrybbq.github.io/NOC-Reports/tests.html)
on the same site.

## Running it locally

Node 18+, no install step — there are no dependencies to fetch.

| Command | What it does |
| --- | --- |
| `npm test` | Node harness — the full suite, non-zero exit on failure |
| `npm run test:browser` | Builds the site and runs `tests.html` in headless Chrome |
| `npm run serve` | Serves `standalone/` on <http://localhost:8000> |
| `npm run build:site` | Builds the Pages payload into `_site/` |

`npm run serve -- 9000` or `PORT=9000 npm run serve` picks a different port.
The test page must be served over HTTP — `file://` blocks ES-module imports in
every modern browser.

`npm run test:browser` uses whatever Chrome or Chromium is already installed;
point `CHROME_PATH` at a binary if it can't find one.

## CI and deployment

- **`ci.yml`** — runs both test routes (Node and headless Chrome) on every push
  and pull request.
- **`pages.yml`** — on push to `main`, runs the suite, builds `_site/`, and
  deploys to Pages. A failing suite blocks the deploy.

`_site/` is generated, not committed: it's `standalone/` copied verbatim plus a
`.nojekyll` marker and a landing `index.html`. The landing page is only
generated when `standalone/index.html` is absent, so when the UI slice lands
there it becomes the site root automatically.

## Where to read next

`standalone/README.md` covers what the parsers and validator do, the common event
shape every vendor parser returns, what the validator blocks versus warns on, and
what is deliberately not built yet.
