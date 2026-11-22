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

/** Splits on `;` outside quotes and parentheses. */
export function splitParams(value: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quote = false;
  let depth = 0;
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (c === '\\' && quote) {
      cur += c + (value[++i] ?? '');
      continue;
    }
    if (c === '"') quote = !quote;
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
  const pieces: Record<string, { parts: string[]; encoded: boolean[] }> = {};
  for (const p of rest) {
    const eq = p.indexOf('=');
    if (eq <= 0) continue;
    const key = p.slice(0, eq).trim().toLowerCase();
    const val = unquote(p.slice(eq + 1));
    const m = /^([^*]+)(?:\*(\d+))?(\*)?$/.exec(key);
    if (!m) continue;
    const entry = (pieces[m[1]] ??= { parts: [], encoded: [] });
    const idx = m[2] ? Number(m[2]) : 0;
    entry.parts[idx] = val;
    entry.encoded[idx] = Boolean(m[3]);
  }
  const params: Record<string, string> = {};
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
  return { value: first.trim().toLowerCase(), params };
}

function decodeBody(body: string, cte: string): Uint8Array {
  switch (cte.trim().toLowerCase()) {
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
    const t = line.replace(/[ \t]*\r?\n$/, '');
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

export function parseMessage(binary: string): MimePart {
  // Tolerate a leading mbox "From " line and stray blank lines before headers.
  return parsePart(binary.replace(/^(?:\s*\r?\n)+/, ''));
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
