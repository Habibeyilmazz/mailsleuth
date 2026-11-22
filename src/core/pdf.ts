import type { AttachmentIssue } from './attachments';
import { binaryToBytes, bytesToBinary } from './encoding';

// Links and risky actions inside a PDF attachment: the "open the attached document" lure puts its real link there.
// shortcut: a token scan of the objects, not a full PDF parser. It reads plain objects and Flate-compressed
// object streams (where PDF 1.5+ writers put link annotations); encrypted PDFs, a /URI given as an indirect
// reference and links drawn only as text are not read. Upgrade to a real parser if those show up in practice.

export interface PdfInspection {
  uris: string[];
  issues: AttachmentIssue[];
}

const MAX_INFLATED = 32 * 1024 * 1024; // across all object streams: a small PDF can inflate to gigabytes
const MAX_STRING = 8192;

/** Reads a zlib stream as far as it is valid: a stream with trailing bytes or cut short still yields its start. */
async function inflate(data: Uint8Array, budget: number): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let size = 0;
  const reader = new Blob([data as BlobPart]).stream().pipeThrough(new DecompressionStream('deflate')).getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      size += value.length;
      if (size >= budget) break;
    }
  } catch {
    // Damaged or junk-terminated data: keep what was decoded.
  }
  reader.cancel().catch(() => {});
  const out = new Uint8Array(Math.min(size, budget));
  let at = 0;
  for (const c of chunks) {
    const part = c.subarray(0, out.length - at);
    out.set(part, at);
    at += part.length;
  }
  return out;
}

/** PDF names may hide letters as #xx: "/J#61vaScript" is /JavaScript to a reader. */
const decodeName = (n: string) => n.replace(/#([0-9a-f]{2})/gi, (_, h: string) => String.fromCharCode(parseInt(h, 16)));

/** A literal string starting at text[start] === '('. Returns its bytes and the index after the closing paren. */
function readLiteral(text: string, start: number): { value: string; end: number } {
  let depth = 0;
  let value = '';
  let i = start;
  const put = (c: string) => {
    if (value.length < MAX_STRING) value += c;
  };
  for (; i < text.length; i++) {
    const c = text[i];
    if (c === '\\') {
      const n = text[++i];
      if (n === undefined) break;
      if (/[0-7]/.test(n)) {
        let oct = n;
        while (oct.length < 3 && /[0-7]/.test(text[i + 1] ?? '')) oct += text[++i];
        put(String.fromCharCode(parseInt(oct, 8) & 0xff));
      } else if (n === '\r') {
        if (text[i + 1] === '\n') i++; // backslash + line end: continuation
      } else if (n !== '\n') {
        put({ n: '\n', r: '\r', t: '\t', b: '\b', f: '\f' }[n] ?? n);
      }
    } else if (c === '(') {
      if (depth++ > 0) put(c);
    } else if (c === ')') {
      if (--depth === 0) return { value, end: i + 1 };
      put(c);
    } else {
      put(c);
    }
  }
  return { value, end: text.length }; // unterminated: runs to the end, so the scan stays linear
}

/** A PDF string's bytes as text: UTF-16BE with a byte order mark, otherwise UTF-8 (URIs are meant to be ASCII). */
function stringText(bin: string): string {
  const bytes = binaryToBytes(bin);
  return bin.startsWith('\xFE\xFF') ? new TextDecoder('utf-16be').decode(bytes.subarray(2)) : new TextDecoder().decode(bytes);
}

interface Scan {
  uris: string[];
  names: Set<string>;
  fileNames: string[];
}

/**
 * One pass over PDF syntax: names, strings, comments, and stream data skipped as a whole, so a "(" in a comment
 * or binary data cannot swallow later objects and a "stream" inside a string is not taken for one.
 * Object streams (Flate, no predictor) are collected for inflating when `objectStreams` is given.
 */
function scanObjects(text: string, out: Scan, objectStreams?: Uint8Array[]) {
  const token = /\/([^\s/<>[\]()%{}]*)|\(|<([0-9A-Fa-f\s]*)>|%[^\r\n]*|\bobj\b|\bstream(?:\r\n|\r|\n)?/g;
  let prev = '';
  let dict = new Set<string>(); // names since the last "obj": the dictionary of the next stream
  for (let m = token.exec(text); m; m = token.exec(text)) {
    const t = m[0];
    if (m[1] !== undefined) {
      prev = decodeName(m[1]);
      out.names.add(prev);
      dict.add(prev);
      continue;
    }
    if (t[0] === '%') continue;
    if (t === 'obj') {
      dict = new Set();
      continue;
    }
    if (t.startsWith('stream')) {
      const e = text.indexOf('endstream', token.lastIndex);
      const end = e < 0 ? text.length : e;
      if (objectStreams && dict.has('ObjStm') && (dict.has('FlateDecode') || dict.has('Fl')) && !dict.has('DecodeParms')) {
        objectStreams.push(binaryToBytes(text.slice(token.lastIndex, end)));
      }
      token.lastIndex = e < 0 ? text.length : e + 9;
      dict = new Set();
      continue;
    }
    let bin: string;
    if (t === '(') {
      const lit = readLiteral(text, m.index);
      bin = lit.value;
      token.lastIndex = lit.end;
    } else {
      const hex = m[2].replace(/\s/g, '').slice(0, MAX_STRING * 2);
      bin = (hex.length % 2 ? hex + '0' : hex).replace(/../g, (h) => String.fromCharCode(parseInt(h, 16)));
    }
    const value = stringText(bin).trim();
    if (prev === 'URI' && /^[a-z][a-z0-9+.-]*:|^\\\\/i.test(value)) out.uris.push(value); // encrypted strings are noise
    if ((prev === 'UF' || prev === 'F') && /\.[a-z0-9]{1,8}$/i.test(value) && !value.includes('://')) out.fileNames.push(value);
    prev = '';
  }
}

export async function inspectPdf(bytes: Uint8Array): Promise<PdfInspection> {
  const scan: Scan = { uris: [], names: new Set(), fileNames: [] };
  const objectStreams: Uint8Array[] = [];
  scanObjects(bytesToBinary(bytes), scan, objectStreams);
  let budget = MAX_INFLATED;
  for (const data of objectStreams) {
    if (budget <= 0) break;
    const inflated = await inflate(data, budget);
    budget -= inflated.length;
    scanObjects(bytesToBinary(inflated), scan);
  }

  const issues: AttachmentIssue[] = [];
  if (scan.names.has('Encrypt')) issues.push({ id: 'pdf-encrypted', detail: 'the PDF is encrypted, so the links and actions inside it could not be read' });
  if (scan.names.has('Launch')) issues.push({ id: 'pdf-launch', detail: 'the PDF has a Launch action, which asks the reader to open a file or start a program' });
  if (scan.names.has('JavaScript') || scan.names.has('JS')) issues.push({ id: 'pdf-javascript', detail: 'the PDF contains JavaScript, which runs when it is opened or when you click' });
  if (scan.names.has('EmbeddedFile') || scan.names.has('EmbeddedFiles')) {
    const names = [...new Set(scan.fileNames)].slice(0, 5);
    issues.push({ id: 'pdf-embedded-file', detail: `the PDF carries an embedded file${names.length ? ` (${names.join(', ')})` : ''} that was not inspected` });
  }
  return { uris: [...new Set(scan.uris)], issues };
}
