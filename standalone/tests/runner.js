// Tiny in-browser test runner. No dependencies, no framework.
//
// A test registers itself with test("name", async () => { ... }); the runner
// walks the registered list, catches failures per test, and dumps a coloured
// pass/fail report into the DOM. Fixture files are fetched over HTTP — this
// page must be served (e.g. `python -m http.server`) because file:// blocks
// ES-module imports.

const REGISTRY = [];

export function test(name, fn) { REGISTRY.push({ name, fn }); }

// Assertions.
export function assertEqual(actual, expected, message) {
  if (actual === expected) return;
  const msg = message || "assertEqual";
  throw new Error(`${msg}\n  expected: ${JSON.stringify(expected)}\n  actual:   ${JSON.stringify(actual)}`);
}
export function assertDeepEqual(actual, expected, message) {
  const a = JSON.stringify(actual);
  const b = JSON.stringify(expected);
  if (a === b) return;
  throw new Error(`${message || "assertDeepEqual"}\n  expected: ${b}\n  actual:   ${a}`);
}
export function assertTrue(v, message) { if (!v) throw new Error(message || `assertTrue: got ${v}`); }
export function assertFalse(v, message) { if (v) throw new Error(message || `assertFalse: got ${v}`); }
export function assertIncludes(hay, needle, message) {
  if (Array.isArray(hay)) { if (hay.includes(needle)) return; }
  else if (String(hay).includes(needle)) return;
  throw new Error(`${message || "assertIncludes"}\n  expected to include: ${JSON.stringify(needle)}\n  actual: ${JSON.stringify(hay)}`);
}
export function assertMatch(actual, regex, message) {
  if (regex.test(String(actual))) return;
  throw new Error(`${message || "assertMatch"}\n  expected to match: ${regex}\n  actual: ${JSON.stringify(actual)}`);
}
export function assertThrows(fn, expectedMsgPart, message) {
  try { fn(); }
  catch (e) {
    if (!expectedMsgPart || String(e.message).includes(expectedMsgPart)) return;
    throw new Error(`${message || "assertThrows"}: got wrong error "${e.message}", expected to contain "${expectedMsgPart}"`);
  }
  throw new Error(message || "assertThrows: no error thrown");
}

// Fixture loader
export async function loadFixture(path) {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`Fixture load failed: ${path} (${res.status})`);
  return res.text();
}

// Run and render.
export async function runAll(target) {
  const inBrowser = typeof document !== "undefined";
  const el = inBrowser ? (target || document.getElementById("results")) : null;
  if (el) el.innerHTML = "";
  let pass = 0, fail = 0;
  const failures = [];
  for (const { name, fn } of REGISTRY) {
    let row;
    if (el) {
      row = document.createElement("div");
      row.className = "test pending";
      row.textContent = `⋯ ${name}`;
      el.appendChild(row);
    }
    try {
      await fn();
      if (row) { row.className = "test pass"; row.textContent = `✓ ${name}`; }
      else console.log(`✓ ${name}`);
      pass++;
    } catch (e) {
      if (row) {
        row.className = "test fail";
        row.innerHTML = `<div class="fail-name">✗ ${escapeHtml(name)}</div><pre class="fail-msg">${escapeHtml(e.message)}</pre>${e.stack ? `<pre class="fail-stack">${escapeHtml(e.stack)}</pre>` : ""}`;
      } else {
        console.error(`✗ ${name}\n  ${e.message}`);
      }
      failures.push({ name, error: e });
      fail++;
    }
  }
  if (el) {
    const summary = document.createElement("div");
    summary.className = `summary ${fail === 0 ? "all-pass" : "some-fail"}`;
    summary.textContent = `${pass} passed, ${fail} failed, ${REGISTRY.length} total`;
    el.prepend(summary);
  } else {
    console.log(`\n${pass} passed, ${fail} failed, ${REGISTRY.length} total`);
  }
  return { pass, fail, total: REGISTRY.length, failures };
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[c]));
}
