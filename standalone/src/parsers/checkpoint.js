// Check Point IPS Blade parser.
//
// Consumes the conventional CSV export (header row, one event per row) and
// emits normalised event objects sharing the shape defined below with the
// Fortinet parser. Analysis code downstream cares only about the shape, not
// the vendor.
//
// Normalisation applied here:
//   - Destination "Label_IP (IP)" split into { label, ip }.
//   - Multiple CVEs extracted from Protection Name.
//   - Microsoft bulletin prefix (MS15-034 etc.) kept alongside the CVE.
//   - Suppression count is preserved and never merged into log-event count.
//   - Payload URLs in the Resource field are extracted then the resource is
//     defanged before we hand it downstream.
//   - Raw action string is preserved; mapping to prevented/accepted is a
//     separate field so downstream can show both.

import { parseHeaderCsv } from "./csv.js";
import { extractCves, extractBulletins } from "../cve.js";
import { defangUrlsInText, extractUrls } from "../defang.js";
import { mapAction } from "../action-map.js";

// Column-name candidates. Check Point exports vary slightly by version and by
// the reporter that produced them; we accept the common variants and fall back
// gracefully rather than hard-fail on a rename.
const COLUMN_CANDIDATES = {
  time:        ["Time", "Log Time", "Date", "Timestamp"],
  action:      ["Action"],
  severity:    ["Severity"],
  source:      ["Source", "Source IP", "Src"],
  destination: ["Destination", "Destination IP", "Dst"],
  protection:  ["Protection Name", "Attack Name", "Protection"],
  resource:    ["Resource", "HTTP URL", "URL"],
  suppression: [
    "Suppressed Logs", "Aggregated Log Count", "Log Count",
    "Total Logs", "Suppression Count",
  ],
};

function pickColumn(headers, candidates) {
  for (const c of candidates) {
    const found = headers.find(h => h.toLowerCase() === c.toLowerCase());
    if (found) return found;
  }
  return null;
}

// Extract label and IP from Check Point's compound destination format.
// Handles:
//   "NHS-SC_62.172.145.168 (62.172.145.168)"        -> { label:"NHS-SC", ip:"62.172.145.168" }
//   "analytics.supplychain.nhs.uk_81.144.150.138 (81.144.150.138)"
//   "10.20.30.40"                                    -> { label:"",  ip:"10.20.30.40" }
//   "some.host.name"                                 -> { label:"some.host.name", ip:"" }
export function splitDestination(raw) {
  if (!raw) return { label: "", ip: "" };
  const s = String(raw).trim();
  const paren = s.match(/^(.*?)\s*\((\d{1,3}(?:\.\d{1,3}){3})\)\s*$/);
  if (paren) {
    const prefix = paren[1];
    const ip = paren[2];
    // strip trailing "_<ip>" from the prefix
    const label = prefix.replace(new RegExp("_?" + ip.replace(/\./g, "\\.") + "$"), "");
    return { label, ip };
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(s)) return { label: "", ip: s };
  return { label: s, ip: "" };
}

// Same treatment for the source column, which is usually a bare IP but the
// occasional export ships "hostname (IP)" too.
export function splitSource(raw) {
  if (!raw) return { ip: "", host: "" };
  const s = String(raw).trim();
  const paren = s.match(/^(.*?)\s*\((\d{1,3}(?:\.\d{1,3}){3})\)\s*$/);
  if (paren) return { host: paren[1].trim(), ip: paren[2] };
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(s)) return { ip: s, host: "" };
  return { host: s, ip: "" };
}

function toInt(x) {
  if (x === undefined || x === null || x === "") return 0;
  const n = parseInt(String(x).replace(/[,\s]/g, ""), 10);
  return Number.isFinite(n) ? n : 0;
}

function tsParse(s) {
  if (!s) return null;
  const d = new Date(s);
  return isNaN(d) ? null : d;
}

// Turn one Check Point row into a normalised event.
function normaliseRow(rec, cols) {
  const protection = cols.protection ? rec[cols.protection] || "" : "";
  const cves = extractCves(protection);
  const bulletins = extractBulletins(protection);
  const resource = cols.resource ? rec[cols.resource] || "" : "";
  const urls = extractUrls(resource);
  const src = splitSource(cols.source ? rec[cols.source] : "");
  const dst = splitDestination(cols.destination ? rec[cols.destination] : "");
  const rawAction = cols.action ? rec[cols.action] || "" : "";
  const severity = cols.severity ? rec[cols.severity] || "" : "";
  const suppressed = cols.suppression ? toInt(rec[cols.suppression]) : 0;
  const timeRaw = cols.time ? rec[cols.time] || "" : "";
  return {
    vendor: "checkpoint",
    timestamp: timeRaw,
    timestampParsed: tsParse(timeRaw),
    action: { raw: rawAction, mapped: mapAction(rawAction) },
    severity,
    source: src,
    destination: dst,
    destinationPort: "",
    protection: { name: protection, id: "" },
    cves,
    bulletins,
    urls,                                        // raw URLs — for extraction lists
    resource: defangUrlsInText(resource),        // defanged everywhere else
    logEvents: 1,
    suppressed,
    totalOccurrences: 1 + suppressed,
    profile: "",
    device: { id: "", name: "" },
    raw: rec,
  };
}

// Parse a CSV string and produce:
//   events:   array of normalised events
//   headers:  the actual header row seen
//   columns:  the resolved column mapping (or null where a candidate is missing)
//   preflight: field coverage summary — how many rows had each expected column
//              populated. Used by the validator to catch wrong-file-type inputs.
export function parseCheckpoint(text) {
  const { headers, records } = parseHeaderCsv(text);
  const cols = {};
  for (const key of Object.keys(COLUMN_CANDIDATES)) {
    cols[key] = pickColumn(headers, COLUMN_CANDIDATES[key]);
  }
  // Filter blatant export-artefact rows: some Check Point exports end with a
  // "Failed exporting table." message row. Guard on presence of a source or
  // destination value.
  const kept = records.filter(r => {
    if (cols.time && r[cols.time] === "Failed exporting table.") return false;
    const hasSrc = cols.source && r[cols.source] && String(r[cols.source]).trim() !== "";
    const hasDst = cols.destination && r[cols.destination] && String(r[cols.destination]).trim() !== "";
    return hasSrc || hasDst;
  });
  // Field coverage measured against kept rows only — a single trailing junk
  // row would otherwise skew the coverage of every column.
  const coverage = {};
  for (const key of Object.keys(COLUMN_CANDIDATES)) {
    const col = cols[key];
    if (!col) { coverage[key] = { column: null, populated: 0, total: kept.length, pct: 0 }; continue; }
    let n = 0;
    for (const r of kept) if (r[col] && String(r[col]).trim() !== "") n++;
    coverage[key] = {
      column: col,
      populated: n,
      total: kept.length,
      pct: kept.length ? n / kept.length : 0,
    };
  }
  const events = kept.map(r => normaliseRow(r, cols));
  return {
    vendor: "checkpoint",
    headers,
    columns: cols,
    events,
    droppedArtefactRows: records.length - kept.length,
    coverage,
  };
}
