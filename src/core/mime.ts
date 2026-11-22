import { binaryToBytes, decodeBase64, decodeCharset, decodeHeaderValue, decodeQuotedPrintable } from './encoding';

export interface Header {
  name: string;
  /** Unfolded raw value (binary string). Use decodeHeaderValue() for display. */
  raw: string;
}

export interface MimePart {
  headers: Header[];
  /** Lower-cased "type/subtype". */
  contentType: string;
  params: Record<string, string>;
  disposition: string;
  filename: string | null;
  /** Body after Content-Transfer-Encoding decoding. */
  body: Uint8Array;
  children: MimePart[];
}

const MAX_DEPTH = 20;

export function splitHeaderBlock(binary: string): { headerBlock: string; body: string } {
  if (/^\r?\n/.test(binary)) return { headerBlock: '', body: binary.replace(/^\r?\n/, '') };
  const m = /\r?\n\r?\n/.exec(binary);
  if (!m) return { headerBlock: binary, body: '' };
  return { headerBlock: binary.slice(0, m.index), body: binary.slice(m.index + m[0].length) };
}

export function parseHeaders(block: string): Header[] {
  const headers: Header[] = [];
  for (const line of block.split(/\r?\n/)) {
    if (/^[ \t]/.test(line) && headers.length) {
      headers[headers.length - 1].raw += ' ' + line.trim();
      continue;
    }
    const idx = line.indexOf(':');
    // Skip mbox "From " separators and garbage lines without a header name.
    if (idx <= 0 || /\s/.test(line.slice(0, idx))) continue;
    headers.push({ name: line.slice(0, idx), raw: line.slice(idx + 1).trim() });
  }
  return headers;
}

export function getHeader(headers: Header[], name: string): string | null {
  const h = headers.find((x) => x.name.toLowerCase() === name.toLowerCase());
  return h ? h.raw : null;
}

export function getHeaders(headers: Header[], name: string): string[] {
  return headers.filter((x) => x.name.toLowerCase() === name.toLowerCase()).map((x) => x.raw);
}

/**
 * Removes RFC 5322 comments (nested, with \\-escapes) outside quoted strings, in one linear pass;
 * each becomes a space. An unclosed "(" comments out the rest, like a mail parser would.
 */
export function stripComments(s: string): string {
  let out = '';
  let depth = 0;
  let quote = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '\\' && (quote || depth)) {
      if (!depth) out += c + (s[i + 1] ?? '');
      i++;
    } else if (depth) {
      if (c === '(') depth++;
      else if (c === ')' && --depth === 0) out += ' ';
    } else if (c === '(' && !quote) depth++;
    else {
      if (c === '"') quote = !quote;
      out += c;
    }
  }
  return out;
}

/** Splits on `;` outside quotes and parentheses. */
export function splitParams(value: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quote = false;
  let depth = 0;
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (c === '\\' && (quote || depth)) {
      cur += c + (value[++i] ?? '');
      continue;
    }
    // A quote inside a comment is just text: (a"b) must not swallow the following results.
    if (c === '"' && !depth) quote = !quote;
    else if (!quote && c === '(') depth++;
    else if (!quote && c === ')') depth = Math.max(0, depth - 1);
    if (c === ';' && !quote && depth === 0) {
      out.push(cur.trim());
      cur = '';
    } else cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

function unquote(v: string): string {
  v = v.trim();
  return v.startsWith('"') && v.endsWith('"') && v.length >= 2 ? v.slice(1, -1).replace(/\\(.)/g, '$1') : v;
}

/** Parses `type/sub; a=b; c*=utf-8''x%20y` including RFC 2231 continuations. */
export function parseStructuredHeader(raw: string): { value: string; params: Record<string, string> } {
  const [first = '', ...rest] = splitParams(raw);
  // Null-prototype maps: parameter names like "constructor" come from the attacker.
  const pieces: Record<string, { parts: string[]; encoded: boolean[] }> = Object.create(null);
  for (const p of rest) {
    const eq = p.indexOf('=');
    if (eq <= 0) continue;
    const key = stripComments(p.slice(0, eq)).trim().toLowerCase();
    const m = /^([^*]+)(?:\*(\d+))?(\*)?$/.exec(key);
    // RFC 2045's own example is "charset=us-ascii (Plain text)"; "boundary=b (x)" must not hide every part.
    // Extended (*=) values are percent-encoded and have no comments.
    const val = unquote(m?.[3] ? p.slice(eq + 1) : stripComments(p.slice(eq + 1)));
    if (!m) continue;
    const idx = m[2] ? Number(m[2]) : 0;
    if (idx > 64) continue; // real continuations are short; huge indexes would allocate sparse arrays
    const entry = (pieces[m[1]] ??= { parts: [], encoded: [] });
    entry.parts[idx] = val;
    entry.encoded[idx] = Boolean(m[3]);
  }
  const params: Record<string, string> = Object.create(null);
  for (const [name, { parts, encoded }] of Object.entries(pieces)) {
    let charset = 'utf-8';
    let binary = '';
    parts.forEach((part, i) => {
      if (part === undefined) return;
      if (!encoded[i]) {
        binary += part;
        return;
      }
      let data = part;
      if (i === 0) {
        const m = /^([^']*)'[^']*'(.*)$/.exec(part);
        if (m) {
          charset = m[1] || charset;
          data = m[2];
        }
      }
      binary += data.replace(/%([0-9A-Fa-f]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)));
    });
    params[name] = encoded.some(Boolean)
      ? decodeCharset(binaryToBytes(binary), charset)
      : decodeHeaderValue(binary);
  }
  // RFC 2045 allows comments and spaces: "multipart / mixed (report (v2)); boundary=b".
  return { value: stripComments(first).replace(/\s+/g, '').toLowerCase(), params };
}

function decodeBody(body: string, cte: string): Uint8Array {
  switch (stripComments(cte).trim().toLowerCase()) {
    case 'base64':
      return decodeBase64(body);
    case 'quoted-printable':
      return decodeQuotedPrintable(body);
    default:
      return binaryToBytes(body);
  }
}

function splitMultipart(body: string, boundary: string): string[] {
  const parts: string[] = [];
  const lines = body.split(/(?<=\n)/); // keep line endings so part bodies stay byte-exact
  const open = '--' + boundary;
  let cur: string[] | null = null;
  for (const line of lines) {
    // trimEnd, not a regex: /[ \t]*\n$/ is quadratic on long whitespace runs.
    const t = line.startsWith('--') ? line.trimEnd() : '';
    if (t === open || t === open + '--') {
      if (cur) parts.push(cur.join('').replace(/\r?\n$/, ''));
      if (t === open + '--') return parts;
      cur = [];
    } else if (cur) cur.push(line);
  }
  if (cur && cur.length) parts.push(cur.join('').replace(/\r?\n$/, '')); // missing closing boundary
  return parts;
}

export function parsePart(binary: string, depth = 0, defaultType = 'text/plain'): MimePart {
  const { headerBlock, body } = splitHeaderBlock(binary);
  const headers = parseHeaders(headerBlock);
  const ct = parseStructuredHeader(getHeader(headers, 'content-type') ?? defaultType);
  const contentType = /^[\w.+-]+\/[\w.+-]+$/.test(ct.value) ? ct.value : defaultType;
  const disp = parseStructuredHeader(getHeader(headers, 'content-disposition') ?? '');
  const filename = disp.params['filename'] ?? ct.params['name'] ?? null;
  const part: MimePart = {
    headers,
    contentType,
    params: ct.params,
    disposition: disp.value,
    filename,
    body: new Uint8Array(),
    children: [],
  };
  if (contentType.startsWith('multipart/') && ct.params['boundary'] && depth < MAX_DEPTH) {
    const childDefault = contentType === 'multipart/digest' ? 'message/rfc822' : 'text/plain';
    part.children = splitMultipart(body, ct.params['boundary']).map((p) => parsePart(p, depth + 1, childDefault));
  } else {
    part.body = decodeBody(body, getHeader(headers, 'content-transfer-encoding') ?? '7bit');
  }
  return part;
}

const MESSAGE_HEADER = /^(from|to|cc|subject|date|received|message-id|return-path|reply-to|sender|mime-version|content-type|authentication-results|delivered-to|dkim-signature)$/i;

export function parseMessage(binary: string): MimePart {
  // Tolerate a leading mbox "From " line and stray blank lines before headers.
  const trimmed = binary.replace(/^(?:\s*\r?\n)+/, '');
  // Pasted body text without any email header: analyze all of it as the message text
  // instead of reading its first paragraph as (garbage) headers and dropping it.
  const hasHeaders = parseHeaders(splitHeaderBlock(trimmed).headerBlock).some((h) => MESSAGE_HEADER.test(h.name));
  return parsePart(hasHeaders ? trimmed : '\n' + trimmed);
}

export function* walkParts(part: MimePart): Generator<MimePart> {
  yield part;
  for (const c of part.children) yield* walkParts(c);
}

export function isAttachment(part: MimePart): boolean {
  if (part.children.length) return false;
  if (part.disposition === 'attachment' || part.filename) return true;
  return !part.contentType.startsWith('text/') && !part.contentType.startsWith('multipart/');
}
