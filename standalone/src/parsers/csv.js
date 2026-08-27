// Shared CSV tokenisation.
//
// Handles three quirks that appear in the two vendor formats we ingest:
//   1. RFC 4180 double-quoted fields, including doubled quotes ("") inside them.
//   2. Brace-wrapped lists such as {sig-a,sig-b}. The braces stay in the value,
//      commas inside them do not separate fields.
//   3. Backslash-escaped quotes inside quoted values (some Fortinet exports).
//
// These are pure functions with no I/O.

// Split a single logical CSV line into raw field tokens.
// Quotes are stripped from the outside of a fully-quoted field; escaped
// quotes ("" or \") become a single quote. Brace pairs {} are transparent
// to the tokeniser: commas inside them do not split.
export function splitCsvLine(line) {
  const out = [];
  let buf = "";
  let inQuote = false;
  let braceDepth = 0;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inQuote) {
      if (c === '"' && line[i + 1] === '"') { buf += '"'; i++; continue; }
      if (c === '\\' && line[i + 1] === '"') { buf += '"'; i++; continue; }
      if (c === '"') { inQuote = false; continue; }
      buf += c;
      continue;
    }
    if (c === '"') { inQuote = true; continue; }
    if (c === '{') { braceDepth++; buf += c; continue; }
    if (c === '}') { braceDepth = Math.max(0, braceDepth - 1); buf += c; continue; }
    if (c === ',' && braceDepth === 0) { out.push(buf); buf = ""; continue; }
    buf += c;
  }
  out.push(buf);
  return out;
}

// Split multi-line CSV text into logical rows, respecting embedded newlines
// inside quoted values. Empty lines outside quotes are skipped.
export function splitCsvRows(text) {
  const rows = [];
  let buf = "";
  let inQuote = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"' && !(inQuote && text[i + 1] === '"')) {
      inQuote = !inQuote;
      buf += c;
      continue;
    }
    if (c === '"' && inQuote && text[i + 1] === '"') { buf += '""'; i++; continue; }
    if ((c === '\n' || c === '\r') && !inQuote) {
      if (c === '\r' && text[i + 1] === '\n') i++;
      if (buf.length) { rows.push(buf); buf = ""; }
      continue;
    }
    buf += c;
  }
  if (buf.length) rows.push(buf);
  return rows;
}

// Parse a header+rows CSV (Check Point style) into an array of objects.
// Missing / blank columns become empty strings rather than undefined.
export function parseHeaderCsv(text) {
  const rows = splitCsvRows(text);
  if (rows.length === 0) return { headers: [], records: [] };
  const headers = splitCsvLine(rows[0]).map(h => h.trim());
  const records = [];
  for (let i = 1; i < rows.length; i++) {
    const fields = splitCsvLine(rows[i]);
    const rec = {};
    for (let j = 0; j < headers.length; j++) {
      rec[headers[j]] = fields[j] !== undefined ? fields[j] : "";
    }
    records.push(rec);
  }
  return { headers, records };
}

// Parse a headerless key=value CSV (Fortinet style). Each row is a list of
// key=value pairs. Values may be double-quoted (with commas inside) or bare.
// Fields absent from a row are absent from that row's object.
export function parseKeyValueCsv(text) {
  const rows = splitCsvRows(text);
  const records = [];
  for (const row of rows) {
    const rec = parseKeyValueLine(row);
    if (Object.keys(rec).length > 0) records.push(rec);
  }
  return records;
}

export function parseKeyValueLine(line) {
  const rec = {};
  const tokens = splitCsvLine(line);
  for (const raw of tokens) {
    const token = raw.trim();
    if (!token) continue;
    const eq = token.indexOf('=');
    if (eq <= 0) continue;
    const key = token.slice(0, eq).trim();
    let value = token.slice(eq + 1);
    // Strip a surrounding pair of double quotes if present (values that
    // contained embedded commas came through the tokeniser already stripped,
    // but bare `key="value"` tokens without embedded commas still carry them).
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1).replace(/""/g, '"').replace(/\\"/g, '"');
    }
    rec[key] = value;
  }
  return rec;
}
