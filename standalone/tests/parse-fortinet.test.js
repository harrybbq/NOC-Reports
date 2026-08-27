import { test, assertEqual, assertIncludes, assertTrue, loadFixture } from "./runner.js";
import { parseFortinet } from "../src/parsers/fortinet.js";
import { parseKeyValueLine } from "../src/parsers/csv.js";

test("parseKeyValueLine handles bare and quoted values", () => {
  const rec = parseKeyValueLine('date=2026-04-01,time=09:15:22,devname="tpp-edge-01",attack="Test.Attack"');
  assertEqual(rec.date, "2026-04-01");
  assertEqual(rec.time, "09:15:22");
  assertEqual(rec.devname, "tpp-edge-01");
  assertEqual(rec.attack, "Test.Attack");
});

test("parseKeyValueLine keeps commas inside quoted values", () => {
  const rec = parseKeyValueLine('attack="Foo.Bar",ref="MS15-034,CVE-2015-1635"');
  assertEqual(rec.attack, "Foo.Bar");
  assertEqual(rec.ref, "MS15-034,CVE-2015-1635");
});

test("parseKeyValueLine keeps commas inside {brace} lists", () => {
  const rec = parseKeyValueLine('attack="Multi.CVE",ref="{CVE-2023-38831,CVE-2023-4863}"');
  assertEqual(rec.ref, "{CVE-2023-38831,CVE-2023-4863}");
});

test("parseFortinet reads IPS rows with the mapped field set", async () => {
  const csv = await loadFixture("fixtures/fortinet-ips-sample.csv");
  const p = parseFortinet(csv);
  assertEqual(p.events.length, 5);
  const first = p.events[0];
  assertEqual(first.vendor, "fortinet");
  assertEqual(first.protection.name, "Apache.Log4j.Remote.Code.Execution");
  assertEqual(first.protection.id, "51006");
  assertEqual(first.source.ip, "185.177.72.61");
  assertEqual(first.destination.ip, "10.0.0.42");
  assertEqual(first.destinationPort, "443");
  assertEqual(first.action.raw, "dropped");
  assertEqual(first.action.mapped, "prevented");
  assertEqual(first.device.name, "tpp-edge-01");
  assertEqual(first.profile, "ips-standard");
});

test("parseFortinet extracts CVE from ref and MS bulletin from ref", async () => {
  const csv = await loadFixture("fixtures/fortinet-ips-sample.csv");
  const p = parseFortinet(csv);
  const ms = p.events.find(e => e.protection.name.includes("HTTP.sys"));
  assertTrue(ms, "expected MS-bulletin event");
  assertIncludes(ms.cves, "CVE-2015-1635");
  assertIncludes(ms.bulletins, "MS15-034");
});

test("parseFortinet extracts multiple CVEs from a brace-wrapped ref", async () => {
  const csv = await loadFixture("fixtures/fortinet-ips-sample.csv");
  const p = parseFortinet(csv);
  const multi = p.events.find(e => e.protection.name === "Multi.CVE.Exploit.Attempt");
  assertTrue(multi, "expected multi-CVE Fortinet event");
  assertIncludes(multi.cves, "CVE-2023-38831");
  assertIncludes(multi.cves, "CVE-2023-4863");
  assertEqual(multi.cves.length, 2);
});

test("parseFortinet defangs the url field", async () => {
  const csv = await loadFixture("fixtures/fortinet-ips-sample.csv");
  const p = parseFortinet(csv);
  const withUrl = p.events.find(e => e.raw.url && e.raw.url.startsWith("http://malware"));
  assertTrue(withUrl, "expected malware URL row");
  assertTrue(withUrl.resource.startsWith("hxxp://"), "url must be defanged");
  assertTrue(withUrl.resource.includes("[.]"));
});

test("parseFortinet maps action strings across FortiOS vocabulary", async () => {
  const csv = await loadFixture("fixtures/fortinet-ips-sample.csv");
  const p = parseFortinet(csv);
  const dropped = p.events.filter(e => e.action.raw === "dropped");
  const detected = p.events.filter(e => e.action.raw === "detected");
  const pass = p.events.filter(e => e.action.raw === "pass");
  assertTrue(dropped.every(e => e.action.mapped === "prevented"));
  assertTrue(detected.every(e => e.action.mapped === "accepted"));
  assertTrue(pass.every(e => e.action.mapped === "accepted"));
});

test("parseFortinet counts distinct devices, profiles, types, subtypes", async () => {
  const csv = await loadFixture("fixtures/fortinet-ips-sample.csv");
  const p = parseFortinet(csv);
  assertEqual(p.deviceCounts["tpp-edge-01"], 3);
  assertEqual(p.deviceCounts["tpp-edge-02"], 2);
  assertEqual(p.profileCounts["ips-standard"], 4);
  assertEqual(p.profileCounts["ips-monitor"], 1);
  assertEqual(p.typeCounts["utm"], 5);
  assertEqual(p.subtypeCounts["ips"], 5);
});

test("parseFortinet does not fabricate a suppression count", async () => {
  const csv = await loadFixture("fixtures/fortinet-ips-sample.csv");
  const p = parseFortinet(csv);
  const anySuppressed = p.events.some(e => e.suppressed > 0);
  assertTrue(!anySuppressed, "Fortinet events must carry suppressed=0 (field not present)");
});
