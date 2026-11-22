// Minimal Compound File (MS-CFB) and Outlook .msg (MS-OXMSG) writer for synthetic fixtures. Not used by the app.

export interface CfbNode {
  name: string;
  children?: CfbNode[]; // a storage when present, else a stream
  data?: Uint8Array;
}

const FREE = 0xffffffff;
const END = 0xfffffffe;
const FATSECT = 0xfffffffd;
const DIFSECT = 0xfffffffc;

export function makeCfb(rootChildren: CfbNode[], sectorShift: 9 | 12 = 9): Uint8Array {
  const ss = 1 << sectorShift;
  const per = ss / 4;
  interface E { node: CfbNode; type: number; left: number; right: number; child: number; start: number; size: number }
  const entries: E[] = [{ node: { name: 'Root Entry', children: rootChildren }, type: 5, left: FREE, right: FREE, child: FREE, start: END, size: 0 }];
  const order = (a: CfbNode, b: CfbNode) => a.name.length - b.name.length || (a.name.toUpperCase() < b.name.toUpperCase() ? -1 : 1);
  for (let i = 0; i < entries.length; i++) {
    const kids = [...(entries[i].node.children ?? [])].sort(order);
    let prev = -1;
    for (const k of kids) {
      const id = entries.length;
      entries.push({ node: k, type: k.children ? 1 : 2, left: FREE, right: FREE, child: FREE, start: END, size: k.data?.length ?? 0 });
      if (prev < 0) entries[i].child = id;
      else entries[prev].right = id; // a right-leaning chain is a valid (if unbalanced) sibling tree
      prev = id;
    }
  }

  // Small streams live in the mini stream (64-byte sectors), large ones in regular sectors.
  const mini: number[] = [];
  const miniData: Uint8Array[] = [];
  const big: { e: E; sectors: number }[] = [];
  for (const e of entries) {
    if (e.type !== 2 || !e.size) continue;
    if (e.size < 4096) {
      const n = Math.ceil(e.size / 64);
      e.start = mini.length;
      for (let i = 0; i < n; i++) mini.push(i === n - 1 ? END : mini.length + 1);
      const padded = new Uint8Array(n * 64);
      padded.set(e.node.data!);
      miniData.push(padded);
    } else big.push({ e, sectors: Math.ceil(e.size / ss) });
  }
  const miniLen = mini.length * 64;
  const dirN = Math.ceil((entries.length * 128) / ss);
  const miniFatN = Math.ceil((mini.length * 4) / ss);
  const miniN = Math.ceil(miniLen / ss);
  const dataN = dirN + miniFatN + miniN + big.reduce((s, b) => s + b.sectors, 0);
  let fatN = 1;
  let difatN = 0;
  for (;;) {
    difatN = Math.max(0, Math.ceil((fatN - 109) / (per - 1)));
    if (fatN * per >= dataN + fatN + difatN) break;
    fatN++;
  }

  const fat = new Uint32Array(fatN * per).fill(FREE);
  let next = 0;
  const fatIds: number[] = [];
  const difatIds: number[] = [];
  for (let i = 0; i < fatN; i++) fat[(fatIds[i] = next++)] = FATSECT;
  for (let i = 0; i < difatN; i++) fat[(difatIds[i] = next++)] = DIFSECT;
  const run = (n: number) => {
    if (!n) return END;
    const start = next;
    for (let i = 0; i < n; i++, next++) fat[next] = i === n - 1 ? END : next + 1;
    return start;
  };
  const dirStart = run(dirN);
  const miniFatStart = run(miniFatN);
  entries[0].start = run(miniN);
  entries[0].size = miniLen;
  for (const b of big) b.e.start = run(b.sectors);

  const out = new Uint8Array((next + 1) * ss);
  const v = new DataView(out.buffer);
  const at = (sector: number) => (sector + 1) * ss;
  out.set([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
  v.setUint16(0x18, 0x3e, true);
  v.setUint16(0x1a, sectorShift === 12 ? 4 : 3, true);
  v.setUint16(0x1c, 0xfffe, true);
  v.setUint16(0x1e, sectorShift, true);
  v.setUint16(0x20, 6, true);
  if (sectorShift === 12) v.setUint32(0x28, dirN, true);
  v.setUint32(0x2c, fatN, true);
  v.setUint32(0x30, dirStart, true);
  v.setUint32(0x38, 4096, true);
  v.setUint32(0x3c, miniFatStart, true);
  v.setUint32(0x40, miniFatN, true);
  v.setUint32(0x44, difatN ? difatIds[0] : END, true);
  v.setUint32(0x48, difatN, true);
  for (let i = 0; i < 109; i++) v.setUint32(0x4c + i * 4, i < fatN ? fatIds[i] : FREE, true);
  difatIds.forEach((s, d) => {
    for (let i = 0; i < per - 1; i++) {
      const f = 109 + d * (per - 1) + i;
      v.setUint32(at(s) + i * 4, f < fatN ? fatIds[f] : FREE, true);
    }
    v.setUint32(at(s) + (per - 1) * 4, d + 1 < difatN ? difatIds[d + 1] : END, true);
  });
  fatIds.forEach((s, i) => fat.subarray(i * per, (i + 1) * per).forEach((x, j) => v.setUint32(at(s) + j * 4, x, true)));

  const dir = new Uint8Array(dirN * ss);
  const dv = new DataView(dir.buffer);
  entries.forEach((e, i) => {
    const p = i * 128;
    for (let c = 0; c < e.node.name.length; c++) dv.setUint16(p + c * 2, e.node.name.charCodeAt(c), true);
    dv.setUint16(p + 0x40, (e.node.name.length + 1) * 2, true);
    dv.setUint8(p + 0x42, e.type);
    dv.setUint8(p + 0x43, 1); // black
    dv.setUint32(p + 0x44, e.left, true);
    dv.setUint32(p + 0x48, e.right, true);
    dv.setUint32(p + 0x4c, e.child, true);
    dv.setUint32(p + 0x74, e.start, true);
    dv.setUint32(p + 0x78, e.size, true);
  });
  for (let i = entries.length; i < dirN * ss / 128; i++) {
    dv.setUint32(i * 128 + 0x44, FREE, true);
    dv.setUint32(i * 128 + 0x48, FREE, true);
    dv.setUint32(i * 128 + 0x4c, FREE, true);
  }
  const writeChain = (start: number, data: Uint8Array) => {
    for (let s = start, p = 0; s !== END && p < data.length; s = fat[s], p += ss) out.set(data.subarray(p, p + ss), at(s));
  };
  writeChain(dirStart, dir);
  const mf = new Uint8Array(miniFatN * ss).fill(0xff);
  mini.forEach((x, i) => new DataView(mf.buffer).setUint32(i * 4, x, true));
  writeChain(miniFatStart, mf);
  const ms = new Uint8Array(miniLen);
  miniData.reduce((p, d) => (ms.set(d, p), p + d.length), 0);
  writeChain(entries[0].start, ms);
  for (const b of big) writeChain(b.e.start, b.e.node.data!);
  return out;
}

// ---------- .msg on top of CFB ----------

export interface MsgSpec {
  strings?: Record<number, string>;
  /** 8-bit strings (PT_STRING8), stored as given; readers decode them with the message code page. */
  ansi?: Record<number, Uint8Array>;
  binaries?: Record<number, Uint8Array>;
  longs?: Record<number, number>;
  times?: Record<number, Date>;
  recipients?: MsgSpec[];
  attachments?: (MsgSpec & { embedded?: MsgSpec })[];
}

const hex = (n: number, w: number) => n.toString(16).toUpperCase().padStart(w, '0');

function msgNodes(spec: MsgSpec, headerSize: number): CfbNode[] {
  const nodes: CfbNode[] = [];
  const props: number[][] = []; // [tag, size or low, high]
  for (const [id, s] of Object.entries(spec.strings ?? {})) {
    const data = new Uint8Array(s.length * 2);
    for (let i = 0; i < s.length; i++) new DataView(data.buffer).setUint16(i * 2, s.charCodeAt(i), true);
    nodes.push({ name: `__substg1.0_${hex(+id, 4)}001F`, data });
    props.push([(+id << 16) | 0x1f, data.length + 2, 0]);
  }
  for (const [id, data] of Object.entries(spec.ansi ?? {})) {
    nodes.push({ name: `__substg1.0_${hex(+id, 4)}001E`, data });
    props.push([(+id << 16) | 0x1e, data.length + 1, 0]);
  }
  for (const [id, data] of Object.entries(spec.binaries ?? {})) {
    nodes.push({ name: `__substg1.0_${hex(+id, 4)}0102`, data });
    props.push([(+id << 16) | 0x102, data.length, 0]);
  }
  for (const [id, n] of Object.entries(spec.longs ?? {})) props.push([(+id << 16) | 3, n >>> 0, 0]);
  for (const [id, d] of Object.entries(spec.times ?? {})) {
    const ft = BigInt(d.getTime() + 11644473600000) * 10000n;
    props.push([(+id << 16) | 0x40, Number(ft & 0xffffffffn), Number(ft >> 32n)]);
  }
  (spec.recipients ?? []).forEach((r, i) => nodes.push({ name: `__recip_version1.0_#${hex(i, 8)}`, children: msgNodes(r, 8) }));
  (spec.attachments ?? []).forEach((a, i) => {
    const kids = msgNodes(a, 8);
    if (a.embedded) {
      kids.push({ name: '__substg1.0_3701000D', children: msgNodes(a.embedded, 24) });
    }
    nodes.push({ name: `__attach_version1.0_#${hex(i, 8)}`, children: kids });
  });
  const head = new Uint8Array(headerSize);
  if (headerSize >= 24) {
    const hv = new DataView(head.buffer);
    hv.setUint32(8, spec.recipients?.length ?? 0, true);
    hv.setUint32(12, spec.attachments?.length ?? 0, true);
    hv.setUint32(16, spec.recipients?.length ?? 0, true);
    hv.setUint32(20, spec.attachments?.length ?? 0, true);
  }
  const body = new Uint8Array(props.length * 16);
  const bv = new DataView(body.buffer);
  props.forEach(([tag, lo, hi], i) => {
    bv.setUint32(i * 16, tag >>> 0, true);
    bv.setUint32(i * 16 + 4, 6, true); // readable | writable
    bv.setUint32(i * 16 + 8, lo >>> 0, true);
    bv.setUint32(i * 16 + 12, hi >>> 0, true);
  });
  const all = new Uint8Array(head.length + body.length);
  all.set(head);
  all.set(body, head.length);
  nodes.push({ name: '__properties_version1.0', data: all });
  return nodes;
}

export function makeMsg(spec: MsgSpec, sectorShift: 9 | 12 = 9): Uint8Array {
  const nameid: CfbNode = {
    name: '__nameid_version1.0',
    children: ['00020102', '00030102', '00040102'].map((t) => ({ name: `__substg1.0_${t}`, data: new Uint8Array() })),
  };
  return makeCfb([...msgNodes(spec, 32), nameid], sectorShift);
}

/**
 * Compressed RTF (MS-OXRTFCP) using literals only, which every reader accepts; Outlook's own
 * output also uses back-references (covered by a vector in test/msg.test.ts).
 */
export function compressRtf(raw: Uint8Array): Uint8Array {
  const body: number[] = [];
  let w = 207; // dictionary write position after the preset text
  const tokens: (number | null)[] = [...raw, null]; // null: end marker, a reference to the write position
  for (let i = 0; i < tokens.length; i += 8) {
    let control = 0;
    const bytes: number[] = [];
    tokens.slice(i, i + 8).forEach((t, bit) => {
      if (t === null) {
        control |= 1 << bit;
        bytes.push(w >> 4, (w & 15) << 4);
      } else {
        bytes.push(t);
        w = (w + 1) & 4095;
      }
    });
    body.push(control, ...bytes);
  }
  let crc = 0; // the format's CRC-32 starts at 0 and has no final XOR
  for (const b of body) {
    crc ^= b;
    for (let k = 0; k < 8; k++) crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
  }
  const out = new Uint8Array(16 + body.length);
  const v = new DataView(out.buffer);
  v.setUint32(0, body.length + 12, true);
  v.setUint32(4, raw.length, true);
  v.setUint32(8, 0x75465a4c, true); // "LZFu"
  v.setUint32(12, crc >>> 0, true);
  out.set(body, 16);
  return out;
}
