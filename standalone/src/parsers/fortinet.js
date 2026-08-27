// Fortinet FortiGate IPS parser.
//
// Fortinet exports each row as an unordered list of `key="value"` pairs. No
// header row. Fields vary row to row. Values may contain commas inside
// quotes; brace-wrapped lists like {sig-a,sig-b} carry commas that are not
// field separators — both are handled by the CSV tokeniser this imports.

import { parseKeyValueCsv } from "./csv.js";
import { extractCves, extractBulletins } from "../cve.js";
import { defangUrlsInText, extractUrls, defangUrl } from "../defang.js";
import { mapAction } from "../action-map.js";

// Field name aliases as they appear across FortiOS versions.
const FIELD_ALIASES = {
  attack:    ["attack", "attackname", "attack_name"],
  attackid:  ["attackid", "attack_id"],
  severity:  ["severity", "level"],
  ref:       ["ref", "cve"],
  srcip:     ["srcip", "src_ip", "src"],
  srcname:   ["srcname", "src_name", "srchost"],
  dstip:     ["dstip", "dst_ip", "dst"],
  dstport:   ["dstport", "dst_port"],
  service:   ["service"],
  hostname:  ["hostname", "host"],
  url:       ["url"],
  date:      ["date"],
  time:      ["time"],
  profile:   ["profile", "profilegroup"],
  action:    ["action"],
  devid:     ["devid", "device_id"],
  devname:   ["devname", "devicename", "device_name"],
  type:      ["type"],
  subtype:   ["subtype"],
  incidentserialno: ["incidentserialno"],
};

function pick(rec, key) {
  const names = FIELD_ALIASES[key] || [key];
  for (const n of names) {
    if (rec[n] !== undefined && rec[n] !== "") return rec[n];
  }
  return "";
}

function tsParseFortinet(dateStr, timeStr) {
  if (!dateStr) return null;
  const s = timeStr ? `${dateStr}T${timeStr}` : dateStr;
  const d = new Date(s);
  return isNaN(d) ? null : d;
}

function normaliseFortinetRow(rec) {
  const attack = pick(rec, "attack");
  const attackid = pick(rec, "attackid");
  const ref = pick(rec, "ref");
  // CVEs live in ref, but a few FortiOS versions also embed them in attack.
  const cves = Array.from(new Set([...extractCves(ref), ...extractCves(attack)]));
  const bulletins = Array.from(new Set([...extractBulletins(ref), ...extractBulletins(attack)]));
  const url = pick(rec, "url");
  const hostname = pick(rec, "hostname");
  const urls = extractUrls(url).length ? extractUrls(url) : (url ? [url] : []);
  const srcip = pick(rec, "srcip");
  const dstip = pick(rec, "dstip");
  const dstport = pick(rec, "dstport");
  const rawAction = pick(rec, "action");
  const severity = pick(rec, "severity");
  const profile = pick(rec, "profile");
  const devid = pick(rec, "devid");
  const devname = pick(rec, "devname");
  const date = pick(rec, "date");
  const time = pick(rec, "time");
  return {
    vendor: "fortinet",
    timestamp: [date, time].filter(Boolean).join(" ").trim(),
    timestampParsed: tsParseFortinet(date, time),
    action: { raw: rawAction, mapped: mapAction(rawAction) },
    severity,
    source: { ip: srcip, host: pick(rec, "srcname") },
    destination: {
      ip: dstip,
      label: hostname || "",
      port: dstport,
    },
    destinationPort: dstport,
    protection: { name: attack, id: attackid },
    cves,
    bulletins,
    urls,
    resource: url ? defangUrl(url) : (hostname ? defangUrlsInText(hostname) : ""),
    logEvents: 1,
    // Fortinet exports do not carry a per-row suppression count in the
    // documented field set. Report log events only; the Methodology tab
    // states this.
    suppressed: 0,
    totalOccurrences: 1,
    profile,
    device: { id: devid, name: devname },
    raw: rec,
  };
}

// Coverage summary across the expected IPS fields — used by the validator to
// distinguish an IPS export from an accidentally-selected traffic export.
function computeCoverage(records) {
  const keys = ["attack", "attackid", "severity", "srcip", "dstip", "action", "profile", "devid"];
  const coverage = {};
  for (const key of keys) {
    let n = 0;
    for (const r of records) if (pick(r, key)) n++;
    coverage[key] = { populated: n, total: records.length, pct: records.length ? n / records.length : 0 };
  }
  return coverage;
}

function distinctCounts(records, key) {
  const counts = {};
  for (const r of records) {
    const v = pick(r, key);
    if (!v) continue;
    counts[v] = (counts[v] || 0) + 1;
  }
  return counts;
}

export function parseFortinet(text) {
  const records = parseKeyValueCsv(text);
  const events = records.map(normaliseFortinetRow);
  return {
    vendor: "fortinet",
    columns: {},
    events,
    droppedArtefactRows: 0,
    coverage: computeCoverage(records),
    typeCounts: distinctCounts(records, "type"),
    subtypeCounts: distinctCounts(records, "subtype"),
    deviceCounts: distinctCounts(records, "devname"),
    profileCounts: distinctCounts(records, "profile"),
    rawRecords: records,
  };
}
