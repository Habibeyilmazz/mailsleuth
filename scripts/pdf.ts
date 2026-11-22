// Tiny PDF writer for synthetic fixtures. Not used by the app.
import { deflateSync } from 'node:zlib';

/**
 * Objects 1..n are written as plain objects; `packed` ones follow, numbered on, inside one Flate-compressed
 * object stream, the way PDF 1.5+ writers store annotations. Object 1 must be the catalog.
 * shortcut: a classic xref covers only the plain objects, so viewers rebuild the table; enough for analysis fixtures.
 */
export function makePdf(objects: string[], packed: string[] = []): Uint8Array {
  const enc = new TextEncoder();
  const parts: Uint8Array[] = [enc.encode('%PDF-1.7\n%\xE2\xE3\xCF\xD3\n')];
  let size = parts[0].length;
  const offsets: number[] = [];
  const push = (b: Uint8Array) => {
    parts.push(b);
    size += b.length;
  };
  objects.forEach((body, i) => {
    offsets.push(size);
    push(enc.encode(`${i + 1} 0 obj\n${body}\nendobj\n`));
  });
  if (packed.length) {
    let header = '';
    let content = '';
    packed.forEach((body, i) => {
      header += `${objects.length + 1 + i} ${content.length} `;
      content += body + '\n';
    });
    const data = deflateSync(enc.encode(header + content));
    push(enc.encode(`${objects.length + packed.length + 1} 0 obj\n<< /Type /ObjStm /N ${packed.length} /First ${header.length} /Filter /FlateDecode /Length ${data.length} >>\nstream\n`));
    push(data);
    push(enc.encode('\nendstream\nendobj\n'));
  }
  const xref = size;
  const rows = offsets.map((o) => `${String(o).padStart(10, '0')} 00000 n \n`).join('');
  push(enc.encode(`xref\n0 ${offsets.length + 1}\n0000000000 65535 f \n${rows}trailer\n<< /Size ${offsets.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`));
  const out = new Uint8Array(size);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}
