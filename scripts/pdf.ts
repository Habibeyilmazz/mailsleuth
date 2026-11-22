// Tiny PDF writer for synthetic fixtures. Not used by the app.
import { deflateSync } from 'node:zlib';

/**
 * Objects 1..n are written as plain objects; `packed` ones follow, numbered on, inside one Flate-compressed
 * object stream, the way PDF 1.5+ writers store annotations (then with a cross-reference stream, which a
 * reader needs to find them). Object 1 must be the catalog.
 */
export function makePdf(objects: string[], packed: string[] = []): Uint8Array {
  const enc = new TextEncoder();
  const parts: Uint8Array[] = [];
  let size = 0;
  const push = (b: Uint8Array | string) => {
    const bytes = typeof b === 'string' ? enc.encode(b) : b;
    parts.push(bytes);
    size += bytes.length;
  };
  push(packed.length ? '%PDF-1.7\n' : '%PDF-1.4\n');
  push(new Uint8Array([0x25, 0xe2, 0xe3, 0xcf, 0xd3, 0x0a])); // binary comment marking the file as binary
  const offsets: number[] = [];
  objects.forEach((body, i) => {
    offsets.push(size);
    push(`${i + 1} 0 obj\n${body}\nendobj\n`);
  });
  const xref = size;
  if (!packed.length) {
    const rows = offsets.map((o) => `${String(o).padStart(10, '0')} 00000 n \n`).join('');
    push(`xref\n0 ${offsets.length + 1}\n0000000000 65535 f \n${rows}trailer\n<< /Size ${offsets.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`);
  } else {
    const n = objects.length;
    const stmNum = n + packed.length + 1;
    let header = '';
    let content = '';
    packed.forEach((body, i) => {
      header += `${n + 1 + i} ${content.length} `;
      content += body + '\n';
    });
    const data = deflateSync(enc.encode(header + content));
    const stmOffset = size;
    push(`${stmNum} 0 obj\n<< /Type /ObjStm /N ${packed.length} /First ${header.length} /Filter /FlateDecode /Length ${data.length} >>\nstream\n`);
    push(data);
    push('\nendstream\nendobj\n');
    // Cross-reference stream, fields [type(1) field2(4) field3(2)], uncompressed.
    const xrefNum = stmNum + 1;
    const xrefOffset = size;
    const row = (t: number, a: number, b: number) => [t, (a >>> 24) & 255, (a >>> 16) & 255, (a >>> 8) & 255, a & 255, (b >>> 8) & 255, b & 255];
    const rows = [row(0, 0, 0xffff), ...offsets.map((o) => row(1, o, 0)), ...packed.map((_, i) => row(2, stmNum, i)), row(1, stmOffset, 0), row(1, xrefOffset, 0)];
    const table = new Uint8Array(rows.flat());
    push(`${xrefNum} 0 obj\n<< /Type /XRef /Size ${xrefNum + 1} /W [1 4 2] /Root 1 0 R /Length ${table.length} >>\nstream\n`);
    push(table);
    push(`\nendstream\nendobj\nstartxref\n${xrefOffset}\n%%EOF\n`);
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}
