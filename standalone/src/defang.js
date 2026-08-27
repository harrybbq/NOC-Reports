// URL defanging.
//
// A live payload URL in a mailed workbook is a hazard on its own. Every
// generated cell that carries a URL must go through defangUrl() first.
//
// Rules:
//   http://  -> hxxp://
//   https:// -> hxxps://
//   ftp://   -> fxp://
//   .        -> [.]     (in host portion only)
//
// Only the host portion of a URL is dotted-bracketed. Dots in the path stay
// intact — path-dots are not what makes a link clickable.

const SCHEME_MAP = { "http": "hxxp", "https": "hxxps", "ftp": "fxp" };

export function defangUrl(url) {
  if (!url) return url;
  const trimmed = String(url).trim();
  // Full URL with scheme
  const schemeMatch = trimmed.match(/^([a-zA-Z]+):\/\/([^/?#\s]+)(.*)$/);
  if (schemeMatch) {
    const scheme = schemeMatch[1].toLowerCase();
    const host = schemeMatch[2];
    const rest = schemeMatch[3];
    const defScheme = SCHEME_MAP[scheme] || (scheme + "x");
    return `${defScheme}://${host.replace(/\./g, "[.]")}${rest}`;
  }
  // Bare host or host+path with no scheme — dot the host portion up to the first /
  const bareMatch = trimmed.match(/^([^/?#\s]+)(.*)$/);
  if (bareMatch && bareMatch[1].includes(".")) {
    return `${bareMatch[1].replace(/\./g, "[.]")}${bareMatch[2]}`;
  }
  return trimmed;
}

// Defang every URL found in a longer string (Check Point's Resource field can
// carry an attack blob with a live URL embedded in it).
const URL_IN_TEXT_RE = /(https?|ftp):\/\/[^\s<>"'\)]+/gi;
export function defangUrlsInText(text) {
  if (!text) return text;
  return String(text).replace(URL_IN_TEXT_RE, (m) => defangUrl(m));
}

// Extract raw URLs before defanging (useful when we want the URL as its own
// column). Returned URLs are NOT defanged; caller decides.
export function extractUrls(text) {
  if (!text) return [];
  const seen = new Set();
  const out = [];
  const matches = String(text).match(URL_IN_TEXT_RE) || [];
  for (const m of matches) {
    if (!seen.has(m)) { seen.add(m); out.push(m); }
  }
  return out;
}
