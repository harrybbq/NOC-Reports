import { test, assertEqual, assertTrue, assertFalse, assertIncludes, loadFixture } from "./runner.js";
import { validate } from "../src/validate.js";
import { parseCheckpoint } from "../src/parsers/checkpoint.js";
import { parseFortinet } from "../src/parsers/fortinet.js";

function codes(list) { return list.map(x => x.code); }

test("validate rejects a Fortinet traffic file", async () => {
  const csv = await loadFixture("fixtures/fortinet-traffic-sample.csv");
  const p = parseFortinet(csv);
  const v = validate(p);
  assertFalse(v.pass, "traffic file must not pass validation");
  assertIncludes(codes(v.blockers), "fortinet-traffic-file");
  const blocker = v.blockers.find(b => b.code === "fortinet-traffic-file");
  assertTrue(blocker.detail.includes("traffic"));
  assertTrue(blocker.detail.includes("ips"), "message should tell user what was expected");
});

test("validate warns on single-action (Prevent-only) export", async () => {
  const csv = await loadFixture("fixtures/checkpoint-prevent-only.csv");
  const p = parseCheckpoint(csv);
  const v = validate(p);
  assertTrue(v.pass, "Prevent-only file should still pass validation");
  assertIncludes(codes(v.warnings), "single-action");
});

test("validate flags low-volume input without failing or dividing by zero", async () => {
  const csv = await loadFixture("fixtures/checkpoint-tiny.csv");
  const p = parseCheckpoint(csv);
  const v = validate(p);
  assertTrue(v.pass, "5-row input passes");
  assertIncludes(codes(v.warnings), "low-volume");
  // preflight numbers must be sane
  assertEqual(v.preflight.recordCount, 5);
  assertTrue(v.preflight.dataDays >= 1);
  for (const key of Object.keys(v.preflight.fieldCoverage)) {
    const pct = v.preflight.fieldCoverage[key];
    assertTrue(pct >= 0 && pct <= 1, `coverage ${key}=${pct} out of range`);
    assertTrue(!Number.isNaN(pct), `coverage ${key} is NaN`);
  }
});

test("validate reports actual data date range regardless of caller label", async () => {
  const csv = await loadFixture("fixtures/checkpoint-sample.csv");
  const p = parseCheckpoint(csv);
  const v = validate(p, { periodLabel: "1 April – 30 April 2026" });
  assertTrue(v.preflight.firstEvent.startsWith("2026-04-01"));
  assertTrue(v.preflight.lastEvent.startsWith("2026-04-04"));
});

test("validate raises narrow-date-range when data is shorter than label", async () => {
  const csv = await loadFixture("fixtures/checkpoint-sample.csv");
  const p = parseCheckpoint(csv);
  const v = validate(p, { periodLabel: "1 January 2026 – 30 April 2026" });
  assertIncludes(codes(v.warnings), "narrow-date-range");
});

test("validate does NOT raise narrow-date-range when label matches data", async () => {
  const csv = await loadFixture("fixtures/checkpoint-sample.csv");
  const p = parseCheckpoint(csv);
  const v = validate(p, { periodLabel: "1 April 2026 – 4 April 2026" });
  assertFalse(codes(v.warnings).includes("narrow-date-range"),
    "period matches data range within margin");
});

test("validate: preflight totals never merge suppressed into log events", async () => {
  const csv = await loadFixture("fixtures/checkpoint-sample.csv");
  const p = parseCheckpoint(csv);
  const v = validate(p);
  assertEqual(v.preflight.recordCount, 6, "6 log-event rows");
  assertTrue(v.preflight.totalOccurrences > 6, "occurrences includes suppression");
  assertEqual(v.preflight.rowsWithSuppression, 3, "3 rows carry suppressed>0 (17, 3, 42)");
});
