// Pre-flight validator.
//
// The old tool silently accepted the wrong log type and shipped a valid-looking
// but empty workbook — read as "no attacks found" when the truth was "wrong
// file". This module refuses to produce a report in that case and, when the
// input is valid but limited, raises visible warnings that will surface both
// in the UI and on the delivered workbook's Scope & Limitations tab.
//
// Result shape:
//   {
//     pass:       boolean,
//     blockers:   [{ code, message, detail? }],   // non-empty => hard fail
//     warnings:   [{ code, message, detail? }],
//     preflight:  { ...summary shown to the user before analysis runs }
//   }

const FORTIANALYZER_HARD_CAP = 100000;
const LOW_VOLUME_THRESHOLD    = 50;
const NARROW_DATE_MARGIN_DAYS = 3;

function distinctCounts(events, path) {
  const counts = {};
  for (const e of events) {
    const v = path(e);
    if (!v) continue;
    counts[v] = (counts[v] || 0) + 1;
  }
  return counts;
}

function fieldCoveragePct(events, path) {
  if (events.length === 0) return 0;
  let n = 0;
  for (const e of events) if (path(e)) n++;
  return n / events.length;
}

function dateRange(events) {
  let min = null, max = null;
  for (const e of events) {
    const d = e.timestampParsed;
    if (!d) continue;
    if (!min || d < min) min = d;
    if (!max || d > max) max = d;
  }
  return { min, max };
}

// Check what the caller declared as their reporting period, compared against
// the actual timestamp range in the data. Returns { periodStart, periodEnd, days }
// or null if the caller did not supply a period.
export function parsePeriodLabel(label) {
  if (!label) return null;
  // Loose parse — try to find two dates in the label.
  const dateMatches = label.match(/(\d{1,2}\s+\w+(?:\s+\d{4})?|\d{4}-\d{2}-\d{2})/g);
  if (!dateMatches || dateMatches.length < 2) return null;
  const start = new Date(dateMatches[0]);
  const end = new Date(dateMatches[1]);
  if (isNaN(start) || isNaN(end)) return null;
  return { periodStart: start, periodEnd: end, days: Math.round((end - start) / 86400000) + 1 };
}

// Runs against a parser result. `sourceKind` is 'checkpoint' or 'fortinet' —
// used to enforce Fortinet-specific rejection rules (traffic vs. IPS export).
export function validate(parseResult, opts = {}) {
  const events = parseResult.events || [];
  const blockers = [];
  const warnings = [];

  // Vendor-specific hard rejections
  if (parseResult.vendor === "fortinet") {
    const types = Object.keys(parseResult.typeCounts || {});
    const nonUtm = types.filter(t => t && t.toLowerCase() !== "utm" && t.toLowerCase() !== "attack");
    const trafficRows = (parseResult.typeCounts || {})["traffic"] || 0;
    if (trafficRows > 0) {
      blockers.push({
        code: "fortinet-traffic-file",
        message: "This looks like a Fortinet traffic export, not an IPS export.",
        detail: `Found ${trafficRows} rows with type="traffic". Expected type="utm" with subtype="ips". ` +
                `Re-export with the IPS log type selected.`,
      });
    }
    const attackPct = (parseResult.coverage?.attack?.pct) ?? 0;
    const attackidPct = (parseResult.coverage?.attackid?.pct) ?? 0;
    if (events.length > 0 && attackPct < 0.05 && attackidPct < 0.05) {
      blockers.push({
        code: "fortinet-no-ips-fields",
        message: "This file does not appear to carry Fortinet IPS fields.",
        detail: `Neither 'attack' nor 'attackid' is populated on any material share of rows. ` +
                `Types seen: ${nonUtm.join(", ") || "none"}.`,
      });
    }
  }

  // Empty parse
  if (events.length === 0 && blockers.length === 0) {
    blockers.push({
      code: "no-events",
      message: "No parseable events were found in this file.",
      detail: "Check the export type and that the file is not empty.",
    });
  }

  // Distinct action, severity, protection distributions
  const actionCounts = {};
  const severityCounts = {};
  for (const e of events) {
    const a = e.action.raw || "(blank)";
    actionCounts[a] = (actionCounts[a] || 0) + 1;
    const s = e.severity || "(blank)";
    severityCounts[s] = (severityCounts[s] || 0) + 1;
  }
  const distinctActions = Object.keys(actionCounts).filter(k => k !== "(blank)");

  // Single-action warning
  if (distinctActions.length === 1) {
    const only = distinctActions[0];
    warnings.push({
      code: "single-action",
      message: `Only one action value is present: "${only}".`,
      detail: `A single-action export cannot show the prevented-versus-accepted gap. ` +
              `The delivered report will state this prominently in Scope & Limitations. ` +
              `If your policy really is single-action, disregard; otherwise re-export with no action filter.`,
    });
  }

  // Severity-subset warning
  const expectedSeverities = ["Critical", "High", "Medium", "Low"];
  const seenSev = Object.keys(severityCounts).filter(s => s !== "(blank)");
  const missingSev = expectedSeverities.filter(s => !seenSev.some(x => x.toLowerCase() === s.toLowerCase()));
  if (seenSev.length > 0 && missingSev.length > 0 && seenSev.length < expectedSeverities.length) {
    warnings.push({
      code: "severity-subset",
      message: `Only some severity levels are represented (${seenSev.join(", ")}).`,
      detail: `The export may be severity-filtered. Missing: ${missingSev.join(", ")}.`,
    });
  }

  // FortiAnalyzer 100k cap
  if (events.length === FORTIANALYZER_HARD_CAP) {
    warnings.push({
      code: "record-cap",
      message: `Record count is exactly ${FORTIANALYZER_HARD_CAP.toLocaleString()}.`,
      detail: `This is the FortiAnalyzer default download cap and almost certainly means the export was truncated. ` +
              `Re-export with a raised cap or a narrower time window.`,
    });
  }

  // Low-volume warning (never a blocker)
  if (events.length > 0 && events.length < LOW_VOLUME_THRESHOLD) {
    warnings.push({
      code: "low-volume",
      message: `Only ${events.length} events in this file.`,
      detail: `A thin report has been produced. It will state on the summary that the volume is low so it is not mistaken for a complete one.`,
    });
  }

  // Date range vs. declared period label
  const { min, max } = dateRange(events);
  const period = parsePeriodLabel(opts.periodLabel);
  if (period && min && max) {
    const dataDays = Math.round((max - min) / 86400000) + 1;
    if (period.days - dataDays > NARROW_DATE_MARGIN_DAYS) {
      warnings.push({
        code: "narrow-date-range",
        message: "Data date range is materially narrower than the declared period label.",
        detail: `Label: ${period.periodStart.toISOString().slice(0,10)} → ${period.periodEnd.toISOString().slice(0,10)} (${period.days} days). ` +
                `Data: ${min.toISOString().slice(0,10)} → ${max.toISOString().slice(0,10)} (${dataDays} days).`,
      });
    }
  }

  // Coverage — helps a reviewer decide whether the export is fully populated
  const coverage = {
    action:      fieldCoveragePct(events, e => e.action.raw),
    severity:    fieldCoveragePct(events, e => e.severity),
    source:      fieldCoveragePct(events, e => e.source.ip || e.source.host),
    destination: fieldCoveragePct(events, e => e.destination.ip || e.destination.label),
    protection:  fieldCoveragePct(events, e => e.protection.name || e.protection.id),
  };

  const suppressedRows = events.filter(e => e.suppressed > 0).length;
  const totalOccurrences = events.reduce((s, e) => s + e.totalOccurrences, 0);

  const preflight = {
    recordCount: events.length,
    totalOccurrences,
    droppedArtefactRows: parseResult.droppedArtefactRows || 0,
    firstEvent: min ? min.toISOString() : null,
    lastEvent:  max ? max.toISOString() : null,
    dataDays: (min && max) ? Math.round((max - min) / 86400000) + 1 : null,
    distinctActions: actionCounts,
    distinctSeverities: severityCounts,
    fieldCoverage: coverage,
    rowsWithSuppression: suppressedRows,
    devices:  parseResult.deviceCounts  || {},
    profiles: parseResult.profileCounts || {},
    types:    parseResult.typeCounts    || {},
    subtypes: parseResult.subtypeCounts || {},
  };

  return { pass: blockers.length === 0, blockers, warnings, preflight };
}
