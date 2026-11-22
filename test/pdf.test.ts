import { deflateSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { inspectPdf } from '../src/core/pdf';
import { makePdf } from '../scripts/pdf.ts';

const enc = (s: string) => new Uint8Array([...s].map((c) => c.charCodeAt(0)));
const catalog = '<< /Type /Catalog /Pages 2 0 R >>';
const pages = '<< /Type /Pages /Kids [] /Count 0 >>';
const ids = async (b: Uint8Array) => (await inspectPdf(b)).issues.map((i) => i.id);

describe('PDF attachments', () => {
  it('reads URI actions from plain objects', async () => {
    const pdf = makePdf([catalog, pages, '<< /Type /Annot /Subtype /Link /A << /S /URI /URI (https://evil.example/login) >> >>']);
    expect(await inspectPdf(pdf)).toEqual({ uris: ['https://evil.example/login'], issues: [] });
  });

  it('reads URI actions packed in a Flate-compressed object stream', async () => {
    const pdf = makePdf([catalog, pages], ['<< /Type /Annot /Subtype /Link /A << /S /URI /URI (https://packed.example/a?b=1) >> >>']);
    expect(new TextDecoder('latin1').decode(pdf)).not.toContain('packed.example');
    expect((await inspectPdf(pdf)).uris).toEqual(['https://packed.example/a?b=1']);
  });

  it('decodes string escapes, hex strings, UTF-16 and #-escaped names', async () => {
    const pdf = makePdf([
      catalog,
      '<< /S /URI /URI (https://a.example/\\(x\\)\\\r\n/y\\137z) >>',
      '<< /S /URI /URI <68747470733A2F2F622E6578616D706C65> >>',
      '<< /S /URI /U#52I <FEFF0068007400740070003A002F002F0063002E006500780061006D0070006C0065> >>',
      '<< /S /URI /URI (https://d.example/(nested)) >>',
    ]);
    expect((await inspectPdf(pdf)).uris).toEqual(['https://a.example/(x)/y_z', 'https://b.example', 'http://c.example', 'https://d.example/(nested)']);
  });

  it('says when the PDF is encrypted, since its strings are then unreadable', async () => {
    const pdf = makePdf([catalog, '<< /URI <9f3c11aa07> >>', '<< /Filter /Standard /V 5 /R 6 >>']);
    const text = new TextDecoder('latin1').decode(pdf).replace('/Root 1 0 R', '/Root 1 0 R /Encrypt 3 0 R');
    expect(await inspectPdf(enc(text))).toEqual({ uris: [], issues: [{ id: 'pdf-encrypted', detail: expect.any(String) }] });
  });

  it('ignores strings that are not under /URI, and noise that is not a URI', async () => {
    const pdf = makePdf([catalog, '<< /Title (https://title.example) /URI (\x8f\x02garbage) >>']);
    expect((await inspectPdf(pdf)).uris).toEqual([]);
  });

  it('flags JavaScript, Launch and embedded files, also when hidden with #xx in names or in object streams', async () => {
    expect(await ids(makePdf([catalog, '<< /OpenAction << /S /J#61vaScript /JS (app.alert(1)) >> >>']))).toEqual(['pdf-javascript']);
    expect(await ids(makePdf([catalog, pages], ['<< /S /Launch /F (cmd.exe) >>']))).toEqual(['pdf-launch']);
    const embedded = await inspectPdf(makePdf([catalog, '<< /Type /Filespec /F (invoice.pdf.exe) /UF (invoice.pdf.exe) /EF << /F 3 0 R >> >>', '<< /Type /EmbeddedFile /Length 0 >>\nstream\n\nendstream']));
    expect(embedded.issues).toEqual([{ id: 'pdf-embedded-file', detail: expect.stringContaining('(invoice.pdf.exe)') }]);
  });

  it('does not mistake JS-like names or text in streams for actions', async () => {
    const content = deflateSync(enc('BT (/JavaScript /Launch) Tj ET'));
    const pdf = new Uint8Array([...makePdf([catalog, '<< /JSomething 1 /Launcher 2 >>']), ...enc('5 0 obj\n<< /Filter /FlateDecode >>\nstream\n'), ...content, ...enc('\nendstream\nendobj\n')]);
    expect(await ids(pdf)).toEqual([]);
  });

  it('keeps going past "stream" inside a string and reads a truncated object stream as far as it goes', async () => {
    expect((await inspectPdf(makePdf([catalog, '<< /Title (mainstream) /URI (https://after.example) >>']))).uris).toEqual(['https://after.example']);
    // Incompressible padding, so cutting the compressed data in half lands between the two links.
    const pad = Array.from({ length: 4000 }, (_, i) => ((i * 2654435761) >>> 0).toString(36)).join('');
    const full = makePdf([catalog], ['<< /URI (https://first.example) >>', `<< /Pad (${pad}) /URI (https://cut.example) >>`]);
    const text = new TextDecoder('latin1').decode(full);
    const start = text.indexOf('stream\n') + 7;
    const cut = full.subarray(0, start + Math.floor((text.indexOf('endstream') - start) / 2));
    expect((await inspectPdf(cut)).uris).toEqual(['https://first.example']);
  });

  it('cannot be blinded by a "(" in a comment or in stream data, or a fake stream inside a string', async () => {
    const pdf = makePdf([
      catalog,
      '<< /Length 3 >>\nstream\n(((\nendstream',
      '% a comment with ( in it\n<< /Title (>> stream) /A << /S /URI /URI (https://one.example) >> >>',
      '<< /Note (endstream) /URI (https://two.example) >>',
    ]);
    expect((await inspectPdf(pdf)).uris).toEqual(['https://one.example', 'https://two.example']);
  });

  it('stops inflating at the size budget (a small PDF can expand to gigabytes)', async () => {
    const bomb = deflateSync(Buffer.alloc(64 * 1024 * 1024));
    const pdf = new Uint8Array([...enc('%PDF-1.7\n1 0 obj\n<< /Type /ObjStm /Filter /FlateDecode >>\nstream\n'), ...bomb, ...enc('\nendstream\nendobj\n')]);
    const t = performance.now();
    expect(await inspectPdf(pdf)).toEqual({ uris: [], issues: [] });
    expect(performance.now() - t).toBeLessThan(3000);
  });

  it('stays linear on hostile repetition', async () => {
    for (const motif of ['(', 'stream ', '>>stream\n', '/URI (', '<', '\\', '/#41', 'obj<< /Type /ObjStm /Filter /FlateDecode >>stream\n']) {
      const t = performance.now();
      await inspectPdf(enc('%PDF-1.7\n' + motif.repeat(Math.ceil(300_000 / motif.length))));
      expect(performance.now() - t, motif).toBeLessThan(500);
    }
  });
});
