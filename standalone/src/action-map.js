// Central raw-action -> generic classification.
//
// The report's Methodology tab documents this mapping explicitly so a reader
// can always trace how a raw vendor term ended up in a "prevented" or
// "accepted" bucket. Change this table in one place only.

const PREVENTED_ACTIONS = new Set([
  "prevent", "block", "blocked", "drop", "dropped", "reset",
  "reset-server", "reset-client", "deny", "denied",
]);

const ACCEPTED_ACTIONS = new Set([
  "detect", "detected", "accept", "accepted", "pass", "passed",
  "monitor", "monitored", "log", "logged", "allow", "allowed",
]);

export function mapAction(raw) {
  if (!raw) return "other";
  const k = String(raw).toLowerCase().trim();
  if (PREVENTED_ACTIONS.has(k)) return "prevented";
  if (ACCEPTED_ACTIONS.has(k)) return "accepted";
  return "other";
}

// For the Methodology tab: which raw terms were seen and where each mapped.
export function summariseActionMapping(rawValues) {
  const out = { prevented: [], accepted: [], other: [] };
  const seen = new Set();
  for (const v of rawValues) {
    if (seen.has(v)) continue;
    seen.add(v);
    out[mapAction(v)].push(v);
  }
  return out;
}
