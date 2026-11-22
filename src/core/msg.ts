// Outlook .msg support: a Compound File (MS-CFB) holding MAPI properties (MS-OXMSG).
// The message is rebuilt as MIME text so the rest of the analyzer runs on it unchanged.
import { bytesToBinary } from './encoding';

const CFB_MAGIC = '\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1';
const END = 0xfffffffe;
const MAX_EMBED_DEPTH = 4; // analyze() stops recursing at 3 anyway

export function isCompoundFile(binary: string): boolean {
  return binary.startsWith(CFB_MAGIC);
}

interface Entry {
  name: string;
  type: number; // 1 storage, 2 stream, 5 root
  left: number;
  right: number;
  child: number;
  start: number;
  size: number;
}

class Cfb {
  private b: Uint8Array;
  private sectorSize: number;
  private fat: Uint32Array;
  private miniFat: Uint32Array;
  private miniStream: Uint8Array;
  private budget: number; // bytes the streams may still take: overlapping chains cannot multiply the file
  entries: Entry[];
  /** Entries already listed under some storage: a hostile file cannot share one subtree between many storages. */
  claimed = new Set<number>([0]);

  constructor(b: Uint8Array) {
    this.b = b;
    const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const shift = v.getUint16(0x1e, true);
    if (b.length < 512 || (shift !== 9 && shift !== 12) || v.getUint16(0x20, true) !== 6) throw new Error('damaged compound file header');
    this.sectorSize = 1 << shift;
    this.budget = 2 * b.length; // mini streams are read twice: once inside the root stream, once on their own

    // FAT sector numbers: 109 in the header, the rest in a chain of DIFAT sectors.
    const fatSectors: number[] = [];
    const nFat = v.getUint32(0x2c, true);
    for (let i = 0; i < 109 && fatSectors.length < nFat; i++) fatSectors.push(v.getUint32(0x4c + i * 4, true));
    const perSector = this.sectorSize / 4;
    for (let s = v.getUint32(0x44, true), seen = 0; s < END && fatSectors.length < nFat; seen++) {
      if (seen > this.sectorCount() || fatSectors.length > this.sectorCount()) throw new Error('DIFAT chain loops');
      const at = this.offset(s);
      for (let i = 0; i < perSector - 1 && fatSectors.length < nFat; i++) fatSectors.push(v.getUint32(at + i * 4, true));
      s = v.getUint32(at + (perSector - 1) * 4, true);
    }
    this.fat = new Uint32Array(fatSectors.length * perSector);
    fatSectors.forEach((s, i) => {
      const at = this.offset(s);
      for (let j = 0; j < perSector; j++) this.fat[i * perSector + j] = v.getUint32(at + j * 4, true);
    });

    const dir = this.chain(v.getUint32(0x30, true), Infinity);
    this.entries = [];
    for (let p = 0; p + 128 <= dir.length; p += 128) {
      const d = new DataView(dir.buffer, dir.byteOffset + p, 128);
      const nameLen = Math.min(d.getUint16(0x40, true), 64);
      this.entries.push({
        name: new TextDecoder('utf-16le').decode(dir.subarray(p, p + Math.max(0, nameLen - 2))),
        type: d.getUint8(0x42),
        left: d.getUint32(0x44, true),
        right: d.getUint32(0x48, true),
        child: d.getUint32(0x4c, true),
        start: d.getUint32(0x74, true),
        size: d.getUint32(0x78, true), // high 32 bits ignored: no email is 4 GB
      });
    }
    const root = this.entries[0];
    if (root?.type !== 5) throw new Error('missing root entry');
    const mf = this.chain(v.getUint32(0x3c, true), Infinity);
    this.miniFat = new Uint32Array(mf.buffer.slice(mf.byteOffset, mf.byteOffset + (mf.length & ~3)));
    this.miniStream = this.chain(root.start, root.size);
  }

  private sectorCount() {
    return Math.floor(this.b.length / this.sectorSize);
  }

  private offset(sector: number) {
    const at = (sector + 1) * this.sectorSize;
    if (at + this.sectorSize > this.b.length) throw new Error(`sector ${sector} is outside the file`);
    return at;
  }

  /** Follows a FAT chain; a loop or a chain past the end of the file is damage. */
  private chain(start: number, size: number): Uint8Array {
    const parts: Uint8Array[] = [];
    let total = 0;
    for (let s = start; s < END && total < size; ) {
      if (parts.length > this.sectorCount()) throw new Error('sector chain loops');
      const at = this.offset(s);
      parts.push(this.b.subarray(at, at + this.sectorSize));
      total += this.sectorSize;
      s = s < this.fat.length ? this.fat[s] : END;
    }
    return this.take(parts, Math.min(size, total));
  }

  private take(parts: Uint8Array[], size: number): Uint8Array {
    this.budget -= size;
    if (this.budget < 0) throw new Error('streams overlap');
    const out = new Uint8Array(size);
    let p = 0;
    for (const part of parts) {
      if (p >= size) break;
      out.set(part.subarray(0, size - p), p);
      p += part.length;
    }
    return out;
  }

  read(e: Entry): Uint8Array {
    if (e.type !== 2) return new Uint8Array();
    if (e.size >= 4096) return this.chain(e.start, e.size);
    const parts: Uint8Array[] = [];
    let total = 0;
    for (let s = e.start; s < END && total < e.size; ) {
      if (parts.length > this.miniStream.length / 64 || (s + 1) * 64 > this.miniStream.length) throw new Error('damaged mini stream');
      parts.push(this.miniStream.subarray(s * 64, s * 64 + 64));
      total += 64;
      s = s < this.miniFat.length ? this.miniFat[s] : END;
    }
    return this.take(parts, Math.min(e.size, total));
  }

  /** Direct children of a storage (an in-order walk of its sibling tree); each entry is listed once per file. */
  children(e: Entry): Map<string, Entry> {
    const out = new Map<string, Entry>();
    const stack = [e.child];
    while (stack.length) {
      const id = stack.pop()!;
      if (id >= this.entries.length || this.claimed.has(id)) continue;
      this.claimed.add(id);
      const c = this.entries[id];
      out.set(c.name.toUpperCase(), c);
      stack.push(c.left, c.right);
    }
    return out;
  }
}

// Windows code page numbers (PidTagInternetCodepage, \ansicpg) to TextDecoder labels.
export function codepageLabel(cp: number): string {
  if (cp === 65001) return 'utf-8';
  if (cp >= 1250 && cp <= 1258) return `windows-${cp}`;
  if (cp >= 28591 && cp <= 28606) return `iso-8859-${cp - 28590}`;
  return ({ 20127: 'us-ascii', 874: 'windows-874', 932: 'shift_jis', 936: 'gbk', 949: 'euc-kr', 950: 'big5', 20866: 'koi8-r', 21866: 'koi8-u', 51932: 'euc-jp', 50220: 'iso-2022-jp', 54936: 'gb18030' } as Record<number, string>)[cp] ?? 'windows-1252';
}

/** One message (or embedded message) storage: string, binary and fixed-size MAPI properties. */
class PropBag {
  private cfb: Cfb;
  private streams: Map<string, Entry>;
  private fixed = new Map<number, DataView>();

  constructor(cfb: Cfb, storage: Entry, headerSize: number) {
    this.cfb = cfb;
    this.streams = cfb.children(storage);
    const props = this.streams.get('__PROPERTIES_VERSION1.0');
    if (props) {
      const b = cfb.read(props);
      for (let p = headerSize; p + 16 <= b.length; p += 16) {
        const d = new DataView(b.buffer, b.byteOffset + p, 16);
        this.fixed.set(d.getUint32(0, true), new DataView(b.buffer, b.byteOffset + p + 8, 8));
      }
    }
  }

  long(id: number): number | null {
    return this.fixed.get(((id << 16) | 0x0003) >>> 0)?.getInt32(0, true) ?? null;
  }

  time(id: number): Date | null {
    const v = this.fixed.get(((id << 16) | 0x0040) >>> 0);
    if (!v) return null;
    const ms = (v.getUint32(4, true) * 2 ** 32 + v.getUint32(0, true)) / 1e4 - 11644473600000; // FILETIME: 100 ns since 1601
    const d = new Date(ms);
    return Number.isNaN(d.getTime()) ? null : d;
  }

  private stream(id: number, type: string): Entry | undefined {
    return this.streams.get(`__SUBSTG1.0_${id.toString(16).padStart(4, '0').toUpperCase()}${type}`);
  }

  binary(id: number): Uint8Array | null {
    const e = this.stream(id, '0102');
    return e ? this.cfb.read(e) : null;
  }

  string(id: number): string | null {
    const u = this.stream(id, '001F');
    if (u) return new TextDecoder('utf-16le').decode(this.cfb.read(u)).replace(/\0+$/, '');
    const a = this.stream(id, '001E');
    if (a) return new TextDecoder(codepageLabel(this.long(0x3ffd) ?? 1252)).decode(this.cfb.read(a)).replace(/\0+$/, '');
    return null;
  }

  storages(prefix: string): Entry[] {
    return [...this.streams.entries()].filter(([n, e]) => n.startsWith(prefix) && e.type === 1).sort(([a], [b]) => (a < b ? -1 : 1)).map(([, e]) => e);
  }

  sub(id: number, type: string, headerSize: number): PropBag | null {
    const e = this.stream(id, type);
    return e?.type === 1 ? new PropBag(this.cfb, e, headerSize) : null;
  }

  isMessage(): boolean {
    return [...this.streams.keys()].some((n) => n.startsWith('__SUBSTG1.0_'));
  }
}

// ---------- compressed RTF (MS-OXRTFCP) ----------

const RTF_DICT = '{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss \\fmodern \\fscript \\fdecor MS Sans SerifSymbolArialTimes New RomanCourier{\\colortbl\\red0\\green0\\blue0\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx';

export function decompressRtf(b: Uint8Array): Uint8Array {
  if (b.length < 16) return new Uint8Array();
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const rawSize = Math.min(v.getUint32(4, true), b.length * 9); // a 2-byte reference expands to at most 17 bytes
  const type = v.getUint32(8, true);
  if (type === 0x414c454d) return b.slice(16, 16 + rawSize); // "MELA": stored uncompressed
  if (type !== 0x75465a4c) return new Uint8Array(); // not "LZFu"
  const dict = new Uint8Array(4096);
  for (let i = 0; i < RTF_DICT.length; i++) dict[i] = RTF_DICT.charCodeAt(i);
  let w = RTF_DICT.length;
  const out = new Uint8Array(rawSize);
  let o = 0;
  let p = 16;
  while (p < b.length && o < rawSize) {
    const control = b[p++];
    for (let bit = 0; bit < 8 && p < b.length && o < rawSize; bit++) {
      if (!(control & (1 << bit))) {
        out[o++] = dict[w] = b[p++];
        w = (w + 1) & 4095;
        continue;
      }
      if (p + 1 >= b.length) return out.slice(0, o);
      const ref = (b[p] << 8) | b[p + 1];
      p += 2;
      let from = ref >> 4;
      if (from === w) return out.slice(0, o); // end marker
      for (let n = (ref & 15) + 2; n > 0 && o < rawSize; n--) {
        out[o++] = dict[w] = dict[from];
        from = (from + 1) & 4095;
        w = (w + 1) & 4095;
      }
    }
  }
  return out.slice(0, o);
}

// ---------- HTML encapsulated in RTF (MS-OXRTFEX) ----------

const SKIP_GROUPS = new Set(['fonttbl', 'colortbl', 'stylesheet', 'info', 'pict', 'object', 'header', 'footer', 'listtable', 'listoverridetable', 'mhtmltag']);
const SYMBOLS: Record<string, string> = { par: '\r\n', line: '\r\n', tab: '\t', lquote: '&#8216;', rquote: '&#8217;', ldblquote: '&#8220;', rdblquote: '&#8221;', bullet: '&#8226;', endash: '&#8211;', emdash: '&#8212;' };

/** The original HTML of an Outlook "\fromhtml" RTF body, or null for ordinary RTF. Output is in the RTF's code page. */
export function rtfToHtml(rtfBytes: Uint8Array): { html: string; charset: string } | null {
  const rtf = bytesToBinary(rtfBytes);
  if (!/^\{\\rtf1[^{]{0,200}\\fromhtml1/.test(rtf)) return null;
  const cp = /\\ansicpg(\d+)/.exec(rtf.slice(0, 200));
  interface State { skip: boolean; tag: boolean; suppressed: boolean; uc: number }
  let st: State = { skip: false, tag: false, suppressed: false, uc: 1 };
  const stack: State[] = [];
  let groupStart = false;
  let fallback = 0; // characters to drop after \uN
  let out = '';
  const emit = (s: string) => {
    if (fallback > 0) fallback--;
    else if (!st.skip && (st.tag || !st.suppressed)) out += s;
  };
  for (let i = 0; i < rtf.length; ) {
    const c = rtf[i];
    if (c === '{') {
      stack.push(st);
      st = { ...st };
      groupStart = true;
      i++;
      continue;
    }
    if (c === '}') {
      if (stack.length) st = stack.pop()!;
      groupStart = false;
      i++;
      continue;
    }
    if (c === '\r' || c === '\n') {
      i++;
      continue;
    }
    if (c !== '\\') {
      groupStart = false;
      emit(c);
      i++;
      continue;
    }
    const m = /^\\([a-z]{1,32})(-?\d{1,10})? ?/.exec(rtf.slice(i, i + 48));
    if (!m) {
      const sym = rtf[i + 1] ?? '';
      if (sym === "'") {
        groupStart = false;
        emit(String.fromCharCode(parseInt(rtf.slice(i + 2, i + 4), 16) || 0));
        i += 4;
      } else if (sym === '*') {
        i += 2; // the next control word decides: \htmltag is kept, other "\*" destinations skipped
        const next = /^\\([a-z]+)/.exec(rtf.slice(i, i + 40));
        if (next?.[1] === 'htmltag') st.tag = true;
        else st.skip = true;
        groupStart = false;
      } else {
        groupStart = false;
        if (sym === '~') emit('&#160;');
        else if (sym === '{' || sym === '}' || sym === '\\') emit(sym);
        else if (sym === '\r' || sym === '\n') emit('\r\n');
        i += 2;
      }
      continue;
    }
    i += m[0].length;
    const [, word, arg] = m;
    if (groupStart && SKIP_GROUPS.has(word)) st.skip = true;
    groupStart = false;
    if (word === 'htmlrtf') st.suppressed = arg !== '0';
    else if (word === 'uc') st.uc = Math.max(0, Number(arg) || 0);
    else if (word === 'u' && arg) {
      emit(`&#${(Number(arg) + 65536) % 65536};`);
      fallback = st.uc;
    } else if (word === 'bin' && arg) i += Math.max(0, Number(arg));
    else if (Object.hasOwn(SYMBOLS, word)) emit(SYMBOLS[word]);
  }
  return { html: out, charset: codepageLabel(cp ? Number(cp[1]) : 1252) };
}

// ---------- MIME reconstruction ----------

export interface MsgResult {
  /** The message as MIME source (binary string). */
  mime: string;
  /** Whether Outlook kept the original internet headers (PidTagTransportMessageHeaders). */
  transportHeaders: boolean;
  bodyFrom: 'html' | 'rtf' | 'text' | 'none';
}

const STRUCTURE_HEADER = /^(content-type|content-transfer-encoding|content-disposition)\s*:/i;
const enc = new TextEncoder();
const utf8 = (s: string) => bytesToBinary(enc.encode(s));
const oneLine = (s: string) => s.replace(/[\r\n\0]+/g, ' ').trim();
const b64 = (bin: string) => btoa(bin).replace(/.{76}/g, '$&\r\n');
const pct = (s: string) => [...enc.encode(s)].map((x) => (/[A-Za-z0-9._-]/.test(String.fromCharCode(x)) ? String.fromCharCode(x) : `%${x.toString(16).toUpperCase().padStart(2, '0')}`)).join('');

function address(name: string | null, addr: string | null): string | null {
  const a = addr && /@/.test(addr) ? oneLine(addr).replace(/[<>"\s]/g, '') : null;
  const n = name ? oneLine(name).replace(/["\\]/g, '\\$&') : '';
  if (!a) return null;
  return n && n !== a ? `"${n}" <${a}>` : `<${a}>`;
}

function part(contentType: string, body: string, filename?: string): string {
  const disp = filename === undefined ? '' : `Content-Disposition: attachment; filename*=utf-8''${pct(filename)}\r\n`;
  return `Content-Type: ${contentType}\r\n${disp}Content-Transfer-Encoding: base64\r\n\r\n${b64(body)}`;
}

function build(cfb: Cfb, msg: PropBag, depth: number): MsgResult {
  const raw = msg.string(0x007d);
  const headerLines: string[] = [];
  if (raw?.trim()) {
    // Body structure is rebuilt below, so the original Content-* fields would describe the wrong thing.
    let dropping = false;
    for (const line of raw.split(/\r?\n/)) {
      if (!line.trim()) continue; // a blank line would end the header block early
      if (/^[ \t]/.test(line)) {
        if (!dropping) headerLines.push(line);
        continue;
      }
      dropping = STRUCTURE_HEADER.test(line);
      if (!dropping) headerLines.push(line);
    }
  } else {
    const from = address(msg.string(0x0042), msg.string(0x5d02) ?? msg.string(0x0065)) ?? address(msg.string(0x0c1a), msg.string(0x5d01) ?? msg.string(0x0c1f));
    if (from) headerLines.push(`From: ${from}`);
    const to: string[] = [];
    const cc: string[] = [];
    for (const r of msg.storages('__RECIP_VERSION1.0_#')) {
      const bag = new PropBag(cfb, r, 8);
      const a = address(bag.string(0x3001), bag.string(0x39fe) ?? bag.string(0x3003));
      const type = bag.long(0x0c15); // 1 To, 2 Cc, 3 Bcc
      if (a && type !== 3) (type === 2 ? cc : to).push(a);
    }
    if (to.length) headerLines.push(`To: ${to.join(', ')}`);
    if (cc.length) headerLines.push(`Cc: ${cc.join(', ')}`);
    const subject = msg.string(0x0037);
    if (subject) headerLines.push(`Subject: ${oneLine(subject)}`);
    const date = msg.time(0x0039) ?? msg.time(0x0e06);
    if (date) headerLines.push(`Date: ${date.toUTCString().replace('GMT', '+0000')}`);
    const id = msg.string(0x1035);
    if (id) headerLines.push(`Message-ID: ${oneLine(id)}`);
  }

  const parts: string[] = [];
  const text = msg.string(0x1000);
  if (text) parts.push(part('text/plain; charset=utf-8', utf8(text)));
  let bodyFrom: MsgResult['bodyFrom'] = text ? 'text' : 'none';
  const htmlBin = msg.binary(0x1013);
  const htmlStr = htmlBin ? null : msg.string(0x1013);
  if (htmlBin) parts.push(part(`text/html; charset=${codepageLabel(msg.long(0x3fde) ?? 65001)}`, bytesToBinary(htmlBin)));
  else if (htmlStr) parts.push(part('text/html; charset=utf-8', utf8(htmlStr)));
  if (htmlBin || htmlStr) bodyFrom = 'html';
  else {
    const rtf = msg.binary(0x1009);
    const html = rtf && rtfToHtml(decompressRtf(rtf));
    if (html) {
      parts.push(part(`text/html; charset=${html.charset}`, html.html));
      bodyFrom = 'rtf';
    }
  }

  for (const a of msg.storages('__ATTACH_VERSION1.0_#')) {
    const att = new PropBag(cfb, a, 8);
    const name = att.string(0x3707) || att.string(0x3704) || att.string(0x3001) || '';
    const data = att.binary(0x3701);
    if (data) {
      const type = (att.string(0x370e) ?? '').trim().toLowerCase();
      parts.push(part(/^[\w.+-]+\/[\w.+-]+$/.test(type) ? type : 'application/octet-stream', bytesToBinary(data), name || 'unnamed-attachment'));
      continue;
    }
    const inner = depth < MAX_EMBED_DEPTH ? att.sub(0x3701, '000D', 24) : null;
    // shortcut: OLE-object and by-reference attachments (no 0x3701 bytes, or a non-message storage) are left out; rare in mail.
    if (inner?.isMessage()) parts.push(part('message/rfc822', build(cfb, inner, depth + 1).mime, `${(name || 'attached-message').replace(/\.msg$/i, '')}.eml`));
  }

  const boundary = `=_mailsleuth_msg_${depth}`; // base64 bodies can never contain "=_"
  // Header text is Unicode (UTF-16 properties); MIME source is bytes, and RFC 6532 allows UTF-8 headers.
  const head = utf8([...headerLines, `Content-Type: multipart/mixed; boundary="${boundary}"`].join('\r\n'));
  const mime = [head, '', ...parts.flatMap((p) => [`--${boundary}`, p]), `--${boundary}--`, ''].join('\r\n');
  return { mime, transportHeaders: !!raw?.trim(), bodyFrom };
}

/** Rebuilds an Outlook .msg as MIME, or returns null when the compound file is not a message (e.g. a .doc). Throws on a damaged file. */
export function readMsg(bytes: Uint8Array): MsgResult | null {
  const cfb = new Cfb(bytes);
  const msg = new PropBag(cfb, cfb.entries[0], 32);
  return msg.isMessage() ? build(cfb, msg, 0) : null;
}
