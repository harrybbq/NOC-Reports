import { test, assertEqual, assertDeepEqual, assertIncludes, assertTrue, loadFixture } from "./runner.js";
import { parseCheckpoint, splitDestination, splitSource } from "../src/parsers/checkpoint.js";

test("splitDestination handles Label_IP (IP)", () => {
  const r = splitDestination("NHS-SC_62.172.145.168 (62.172.145.168)");
  assertEqual(r.label, "NHS-SC");
  assertEqual(r.ip, "62.172.145.168");
});

test("splitDestination handles label with dots and underscores", () => {
  const r = splitDestination("analytics.supplychain.nhs.uk_81.144.150.138 (81.144.150.138)");
  assertEqual(r.label, "analytics.supplychain.nhs.uk");
  assertEqual(r.ip, "81.144.150.138");
});

test("splitDestination handles bare IP", () => {
  const r = splitDestination("10.20.30.40");
  assertEqual(r.label, "");
  assertEqual(r.ip, "10.20.30.40");
});

test("splitSource handles hostname (IP)", () => {
  const r = splitSource("host.example.com (203.0.113.5)");
  assertEqual(r.host, "host.example.com");
  assertEqual(r.ip, "203.0.113.5");
});

test("parseCheckpoint drops 'Failed exporting table.' artefact row", async () => {
  const csv = await loadFixture("fixtures/checkpoint-sample.csv");
  const p = parseCheckpoint(csv);
  assertEqual(p.droppedArtefactRows, 1, "expected one artefact row dropped");
  assertEqual(p.events.length, 6);
});

test("parseCheckpoint extracts multiple CVEs from a single protection", async () => {
  const csv = await loadFixture("fixtures/checkpoint-sample.csv");
  const p = parseCheckpoint(csv);
  const multi = p.events.find(e => e.protection.name.includes("CVE-2023-38831"));
  assertTrue(multi, "expected the multi-CVE event to be present");
  assertIncludes(multi.cves, "CVE-2023-38831");
  assertIncludes(multi.cves, "CVE-2023-4863");
  assertEqual(multi.cves.length, 2);
});

test("parseCheckpoint retains Microsoft bulletin alongside CVE", async () => {
  const csv = await loadFixture("fixtures/checkpoint-sample.csv");
  const p = parseCheckpoint(csv);
  const ms = p.events.find(e => e.protection.name.includes("MS15-034"));
  assertTrue(ms, "expected the MS15-034 event to be present");
  assertIncludes(ms.cves, "CVE-2015-1635");
  assertIncludes(ms.bulletins, "MS15-034");
});

test("parseCheckpoint preserves suppression separately from log events", async () => {
  const csv = await loadFixture("fixtures/checkpoint-sample.csv");
  const p = parseCheckpoint(csv);
  const first = p.events[0];  // 17 suppressed
  assertEqual(first.logEvents, 1, "logEvents should stay 1 per row");
  assertEqual(first.suppressed, 17, "suppression count preserved");
  assertEqual(first.totalOccurrences, 18, "total = 1 log event + 17 suppressed");
  // No aggregation of suppressed into log events anywhere
  const totalLog = p.events.reduce((s, e) => s + e.logEvents, 0);
  const totalOcc = p.events.reduce((s, e) => s + e.totalOccurrences, 0);
  assertEqual(totalLog, p.events.length);
  assertTrue(totalOcc > totalLog, "occurrences should exceed log events when suppression is present");
});

test("parseCheckpoint defangs URLs in the Resource field", async () => {
  const csv = await loadFixture("fixtures/checkpoint-sample.csv");
  const p = parseCheckpoint(csv);
  const withUrl = p.events.find(e => e.raw.Resource && e.raw.Resource.includes("malware.example.com"));
  assertTrue(withUrl, "expected malware URL row present");
  // Extracted raw URLs preserved
  assertIncludes(withUrl.urls, "http://malware.example.com/dropper.exe");
  // Resource field itself is defanged
  assertTrue(!withUrl.resource.includes("http://malware"), "resource must not carry live http://");
  assertTrue(withUrl.resource.includes("hxxp://"), "resource must carry hxxp://");
  assertTrue(withUrl.resource.includes("[.]"), "host dots must be bracketed");
});

test("parseCheckpoint maps Detect to accepted (raw preserved)", async () => {
  const csv = await loadFixture("fixtures/checkpoint-sample.csv");
  const p = parseCheckpoint(csv);
  const det = p.events.find(e => e.action.raw === "Detect");
  assertTrue(det, "expected a Detect row");
  assertEqual(det.action.mapped, "accepted");
});

test("parseCheckpoint classifies each row's action", async () => {
  const csv = await loadFixture("fixtures/checkpoint-sample.csv");
  const p = parseCheckpoint(csv);
  const prevented = p.events.filter(e => e.action.mapped === "prevented").length;
  const accepted = p.events.filter(e => e.action.mapped === "accepted").length;
  assertEqual(prevented, 5);
  assertEqual(accepted, 1);
});

test("parseCheckpoint reports field coverage", async () => {
  const csv = await loadFixture("fixtures/checkpoint-sample.csv");
  const p = parseCheckpoint(csv);
  assertTrue(p.coverage.action.pct > 0.9, "action coverage should be near 100%");
  assertTrue(p.coverage.protection.pct > 0.9);
  assertEqual(p.coverage.severity.column, "Severity");
});
