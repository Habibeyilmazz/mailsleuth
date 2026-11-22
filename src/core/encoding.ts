// Byte/string helpers. Raw messages are handled as "binary strings":
// one JS char per byte (0-255), so MIME offsets stay byte-accurate.

export function bytesToBinary(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    out += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return out;
}

export function binaryToBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

/** Text the user pasted (already Unicode) becomes UTF-8 bytes, like a real .eml file. */
export function textToBinary(text: string): string {
  return bytesToBinary(new TextEncoder().encode(text));
}

export function decodeCharset(bytes: Uint8Array, charset = 'utf-8'): string {
  let label = charset.trim().toLowerCase() || 'utf-8';
  if (label === 'us-ascii' || label === 'ascii') label = 'windows-1252';
  try {
    return new TextDecoder(label).decode(bytes);
  } catch {
    // Unknown charset label: UTF-8 is the most likely real encoding.
    return new TextDecoder('utf-8').decode(bytes);
  }
}

/** Header bytes: RFC 6532 allows raw UTF-8; fall back to Latin-1 for legacy 8-bit junk. */
export function decodeRawHeader(binary: string): string {
  if (!/[\x80-\xff]/.test(binary)) return binary;
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(binaryToBytes(binary));
  } catch {
    return binary;
  }
}

export function decodeBase64(s: string): Uint8Array {
  let clean = s.replace(/[^A-Za-z0-9+/]/g, '');
  clean = clean.slice(0, clean.length - (clean.length % 4 === 1 ? 1 : 0));
  while (clean.length % 4) clean += '=';
  try {
    return binaryToBytes(atob(clean));
  } catch {
    return new Uint8Array();
  }
}

export function decodeQuotedPrintable(s: string, header = false): Uint8Array {
  let text = header ? s.replace(/_/g, ' ') : s.replace(/=\r?\n/g, '');
  text = text.replace(/=([0-9A-Fa-f]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)));
  return binaryToBytes(text);
}

/** RFC 2047 encoded words, e.g. =?UTF-8?B?...?= ; whitespace between adjacent words is dropped. */
export function decodeHeaderValue(raw: string): string {
  const text = decodeRawHeader(raw);
  return text
    .replace(/(\?=)\s+(=\?)/g, '$1$2')
    .replace(/=\?([^?\s]+)\?([BbQq])\?([^?]*)\?=/g, (_, charset: string, enc: string, data: string) => {
      const bytes = enc.toUpperCase() === 'B' ? decodeBase64(data) : decodeQuotedPrintable(data, true);
      return decodeCharset(bytes, charset.split('*')[0]);
    });
}

// Includes the HTML5 names attackers use to hide a scheme from naive scanners ("https&colon;//").
const ENTITIES: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', colon: ':', sol: '/', period: '.', commat: '@',
  quest: '?', equals: '=', num: '#', percnt: '%', lowbar: '_', hyphen: '-', tab: '\t', newline: '\n',
};

export function decodeHtmlEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e: string) => {
    if (e[0] === '#') {
      const code = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : m;
    }
    return Object.hasOwn(ENTITIES, e.toLowerCase()) ? ENTITIES[e.toLowerCase()] : m;
  });
}

/**
 * Visible text of an HTML body. shortcut: regex-based, good enough for scoring words; not a full HTML parser.
 * Every pattern may also end at end of input ("|$"): an unterminated tag then swallows the rest,
 * as in a browser, and thousands of unterminated tags cost one scan instead of one scan each.
 */
export function htmlToText(html: string): string {
  return decodeHtmlEntities(
    html
      .replace(/<(script|style|head)\b[\s\S]*?(?:<\/\1\s*>|$)/gi, ' ')
      .replace(/<!--[\s\S]*?(?:-->|$)/g, ' ')
      .replace(/<(br|\/p|\/div|\/tr|\/li|\/h\d)\b[^>]*(?:>|$)/gi, '\n')
      .replace(/<[^>]+(?:>|$)/g, ' '),
  )
    .replace(/[ \t ]+/g, ' ')
    .replace(/\s*\n\s*/g, '\n')
    .trim();
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}
