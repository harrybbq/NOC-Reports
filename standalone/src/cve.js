// CVE and Microsoft-bulletin extraction.
//
// CVEs may appear multiple times in a single string; we return each unique
// identifier in first-seen order. A Microsoft bulletin prefix (MS15-034,
// MS17-010, etc.) is retained separately so it can be shown alongside the CVE.

const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;
const MS_BULLETIN_RE = /MS\d{2}-\d{3}/g;

export function extractCves(text) {
  if (!text) return [];
  const seen = new Set();
  const out = [];
  const matches = text.match(CVE_RE) || [];
  for (const m of matches) {
    const norm = m.toUpperCase();
    if (!seen.has(norm)) { seen.add(norm); out.push(norm); }
  }
  return out;
}

export function extractBulletins(text) {
  if (!text) return [];
  const seen = new Set();
  const out = [];
  const matches = text.match(MS_BULLETIN_RE) || [];
  for (const m of matches) {
    if (!seen.has(m)) { seen.add(m); out.push(m); }
  }
  return out;
}
