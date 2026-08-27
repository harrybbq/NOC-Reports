# IPS Report Generator — standalone (drop 1: parsers + validator)

This is the **parser and validator** slice of the app you specced. There is no
UI yet — that's next, once you're happy with the classification logic.

## What's in this drop

```
standalone/
├── src/
│   ├── parsers/
│   │   ├── csv.js           shared CSV tokeniser (quotes, {braces}, escapes)
│   │   ├── checkpoint.js    Check Point IPS Blade parser
│   │   └── fortinet.js      Fortinet FortiGate IPS (key="value") parser
│   ├── action-map.js        raw Prevent/Detect/Drop/Pass/… → prevented|accepted
│   ├── cve.js               CVE + Microsoft-bulletin extraction
│   ├── defang.js            URL defanging (hxxp://, [.] on host only)
│   └── validate.js          pre-flight — blockers, warnings, preflight summary
├── tests/
│   ├── fixtures/            synthetic Check Point & Fortinet samples
│   ├── runner.js            tiny test/assert helpers (works in browser and Node)
│   ├── cve-defang.test.js
│   ├── parse-checkpoint.test.js
│   ├── parse-fortinet.test.js
│   └── validate.test.js
├── vendor/
│   └── xlsx-js-style.bundle.js   vendored (no CDN needed at runtime)
├── tests.html               in-browser test runner
├── node-run.js              same suite runnable via Node
├── package.json             only present so Node treats .js as ES modules
└── README.md
```

## Running the tests

**In the browser** (matches the runtime the app will use):

```
cd standalone/
python -m http.server           # or any static server
# then open http://localhost:8000/tests.html
```

It has to be served — opening `tests.html` via `file://` blocks ES-module
imports in every modern browser. That's a browser rule, not a build step.

**In Node** (useful for CI, or a quick console pass):

```
cd standalone/
node node-run.js
```

Both routes exercise the same test files.

From the repo root, `npm test` and `npm run serve` do the same two things
without the `cd` — the server is `scripts/serve.js`, dependency-free, and
serves this directory on port 8000.

Current suite: **39 assertions, all passing.**

## Design notes worth reading before touching the code

- **Everything is a pure function.** Nothing here touches the DOM, the filesystem
  or the network. The Node harness and the browser tests share the exact same
  test files because of this.
- **Parsers return the same shape** regardless of vendor. Downstream analysis
  code will not care whether an event came from Check Point or Fortinet:
  ```
  {
    vendor, timestamp, timestampParsed,
    action:     { raw, mapped },        // 'prevented' | 'accepted' | 'other'
    severity,
    source:     { ip, host },
    destination:{ ip, label, port },
    protection: { name, id },
    cves:       [],                     // "CVE-YYYY-NNNN..." uppercased
    bulletins:  [],                     // "MS15-034" etc.
    urls:       [],                     // raw URLs — NOT defanged
    resource,                           // defanged text for display
    logEvents:  1,
    suppressed: 0,                       // Check Point Suppressed Logs, or 0
    totalOccurrences,                   // 1 + suppressed
    profile, device: { id, name },
    raw:        { ...original record }
  }
  ```
- **Suppression is never merged into log-event counts.** Every event carries
  both `logEvents` (1) and `totalOccurrences` (1 + suppressed). Aggregation
  helpers (coming in the next slice) will compute both figures separately and
  never present one as the other.
- **URLs are defanged in `resource` but preserved raw in `urls`.** The `urls`
  array is what the next slice will feed into the Malware Delivery sheet
  before defanging on output.
- **The action mapping lives in one file** (`src/action-map.js`) so the
  Methodology tab can render it directly and there's a single point of truth
  when new vendor terms turn up.
- **Coverage is measured after artefact rows are dropped** (Check Point
  sometimes trails a "Failed exporting table." row), so a single junk row
  never skews the field-coverage numbers.
- **The validator's job is to fail loudly on the wrong file** and warn
  visibly on the right-but-limited file. It never produces a workbook itself.

## What the validator catches today

Blockers (report generation refused):

- Fortinet file whose rows carry `type="traffic"` — clear message stating what
  was detected and what was expected.
- Fortinet file where neither `attack` nor `attackid` is populated on any
  material share of rows — same reason.
- Zero parseable events after artefact rows are dropped.

Warnings (report still generated, warning surfaces in the UI and later in
Scope & Limitations):

- `single-action` — only one raw action value present (the Prevent-only case
  that has caught us out before).
- `severity-subset` — only some of Critical / High / Medium / Low appear.
- `record-cap` — exactly 100,000 records (FortiAnalyzer's default cap).
- `low-volume` — under 50 events; report still built, just marked thin.
- `narrow-date-range` — data range is materially shorter than the declared
  period label.

Preflight summary always includes:

- Record count and total occurrences after suppression.
- Actual first and last timestamps in the data (not the label).
- Distinct action values and severity values, verbatim, with counts.
- Field coverage per expected column.
- Device and profile inventories (Fortinet).

## What's *not* here yet

Deliberately, so you can sign off on the parsing before the analysis layer
depends on it:

- Aggregation / analysis (Top Attackers, CVE splits, Daily Trend, Sustained
  Activity, etc.)
- Workbook generation (sheet order, styling, defanging on output, the
  Methodology and Scope & Limitations text)
- Findings with stable IDs and the Action Tracker append
- Prior-period upload and recurrence marking
- The UI (`index.html`)
- Config file for RACI, thresholds, per-category default assigned teams
- Local `known-sources.json` and opt-in reverse-DNS

The `vendor/xlsx-js-style.bundle.js` is included ahead of that so the eventual
workbook layer has zero CDN dependency at runtime — vendored, sits offline on
the VDI.

## Tone check — reminders for the analysis and workbook layers

When the next slice lands, the same rules apply:

- The tool emits factual statements with figures, never characterisation of
  intent or risk assessments.
- CVE tabs always split into "accepted" and "fully prevented" — sorted by
  accepted count first — never one big list sorted by volume.
- Exposure Validated / Validation Owner / Validation Notes columns must
  always be produced empty.
- Every defanged URL comes out through `defang.js`. No sheet ever emits
  a live `http://`.
- Suppression figures and log-event figures are labelled distinctly on
  every sheet that shows them.

## Where this lives now

This tree is committed to the `NOC-Reports` repo as `standalone/`. It still runs
exactly as it did in the drop — nothing was rewritten to fit the repo. The repo
root adds `npm test` and `npm run serve` wrappers so you don't have to `cd` in
first; see the root `README.md`.
