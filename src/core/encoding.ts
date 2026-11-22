// Byte/string helpers. Raw messages are handled as "binary strings":
// one JS char per byte (0-255), so MIME offsets stay byte-accurate.

export function bytesToBinary(bytes: Uint8Array): string {
  // apply() with 8 KB chunks is about 7x faster than spreading 32 KB chunks in V8 (26 MB: 480 ms to 60 ms).
  // TextDecoder('latin1') is not an option: it is windows-1252 and changes bytes 0x80-0x9f.
  const parts: string[] = [];
  for (let i = 0; i < bytes.length; i += 0x2000) {
    parts.push(String.fromCharCode.apply(null, bytes.subarray(i, i + 0x2000) as unknown as number[]));
  }
  return parts.join('');
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
  // TextDecoder reads "utf-16" as little-endian; in MIME it means "by the byte order mark, else big-endian" (RFC 2781).
  if (label === 'utf-16') label = bytes[0] === 0xff && bytes[1] === 0xfe ? 'utf-16le' : 'utf-16be';
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
  // "=" then optional transport padding (RFC 2045 6.7) then a line break is a soft break.
  let text = header ? s.replace(/_/g, ' ') : s.replace(/=[ \t]*\r?\n/g, '');
  text = text.replace(/=([0-9A-Fa-f]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)));
  return binaryToBytes(text);
}

/** RFC 2047 encoded words, e.g. =?UTF-8?B?...?= ; whitespace between adjacent words is dropped. */
export function decodeHeaderValue(raw: string): string {
  const text = decodeRawHeader(raw).replace(/(\?=)\s+(=\?)/g, '$1$2');
  // Adjacent words in one charset are joined as bytes before decoding, as mail clients do:
  // senders often split a multi-byte character between two words.
  return text.replace(/(?:=\?[^?\s]+\?[BbQq]\?[^?]*\?=)+/g, (run) => {
    let out = '';
    let charset = '';
    let bytes = '';
    for (const [, cs, enc, data] of run.matchAll(/=\?([^?\s]+)\?([BbQq])\?([^?]*)\?=/g)) {
      const label = cs.split('*')[0].toLowerCase();
      if (label !== charset) {
        if (bytes) out += decodeCharset(binaryToBytes(bytes), charset);
        charset = label;
        bytes = '';
      }
      bytes += bytesToBinary(enc.toUpperCase() === 'B' ? decodeBase64(data) : decodeQuotedPrintable(data, true));
    }
    return out + (bytes ? decodeCharset(binaryToBytes(bytes), charset) : '');
  });
}

// Includes the HTML5 names attackers use to hide a scheme from naive scanners ("https&colon;//"),
// and &shy;, which browsers drop from host names: "pay&shy;pa1.example" opens paypa1.example.
const ENTITIES: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', colon: ':', sol: '/', period: '.', commat: '@',
  quest: '?', equals: '=', num: '#', percnt: '%', lowbar: '_', hyphen: '-', tab: '\t', newline: '\n', shy: '\u00ad',
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
      // Inline tags do not break words in a browser: "ver<span>ify</span>" reads "verify".
      .replace(/<\/?(span|b|i|u|em|strong|font|small|big|sub|sup|s|strike|mark|abbr|a)\b[^>]*(?:>|$)/gi, '')
      // Like browsers, "<" starts a tag only before a letter, "/", "!" or "?"; "price < 5" stays text.
      .replace(/<[a-z/!?][^>]*(?:>|$)/gi, ' '),
  )
    .replace(/[ \t ]+/g, ' ')
    // Per line, not /\s*\n\s*/: that rescans a long run of "\r" from every position.
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .join('\n');
}

// Invisible bidi overrides, embeddings and isolates ("Trojan Source" characters) reorder the text
// around them, so "invoice\u202Efdp.exe" displays as "invoiceexe.pdf".
const BIDI_CONTROLS = /[\u202a-\u202e\u2066-\u2069]/g;

/** Shows each bidi control as a visible "⟨U+202E⟩" marker, so email text cannot reorder what the reader sees. */
export function revealBidi(s: string): string {
  return s.replace(BIDI_CONTROLS, (c) => `⟨U+${c.charCodeAt(0).toString(16).toUpperCase()}⟩`);
}

/**
 * JSON.stringify leaves bidi controls and C1 control characters (U+0080-U+009F) raw, so they
 * reach the terminal: the former reorder lines, the latter are escape codes on some terminals.
 * They can only occur inside JSON strings, where \uXXXX means the same thing.
 */
export function escapeJsonControls(json: string): string {
  return json.replace(/[\u0080-\u009f\u202a-\u202e\u2066-\u2069]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}
