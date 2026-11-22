import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { analyze } from '../src/core/analyze';
import { bytesToBinary } from '../src/core/encoding';
import { parseMessage, walkParts } from '../src/core/mime';
import { decompressRtf, readMsg, rtfToHtml } from '../src/core/msg';
import { makeCfb, makeMsg, type MsgSpec } from '../scripts/msg.ts';

const enc = new TextEncoder();
const sampleBytes = new Uint8Array(readFileSync(new URL('../samples/07-outlook-sign-request.msg', import.meta.url)));
const run = (b: Uint8Array) => analyze(bytesToBinary(b));
const ids = (a: Awaited<ReturnType<typeof analyze>>) => a.findings.map((f) => f.id);

const phishHeaders = 'Received: from relay.bad.example (relay.bad.example [203.0.113.9])\r\n by mx1.example.net with ESMTPS id 1; Wed, 11 Nov 2026 14:02:17 +0000\r\nAuthentication-Results: mx1.example.net; spf=fail smtp.mailfrom=bad.example; dmarc=fail header.from=paypa1-secure.example\r\nFrom: "PayPal" <service@paypa1-secure.example>\r\nSubject: Account limited\r\n';
const phish: MsgSpec = {
  strings: { 0x001a: 'IPM.Note', 0x007d: phishHeaders, 0x0037: 'Account limited' },
  binaries: { 0x1013: enc.encode('<p>Verify your account now: <a href="https://login.paypa1-secure.example/">www.paypal.com</a></p>') },
  longs: { 0x3fde: 65001 },
};

/** Offsets of the directory entries with this name (names are UTF-16LE at the start of a 128-byte entry). */
function entryOffsets(b: Uint8Array, name: string): number[] {
  const needle = name.split('').join('\0') + '\0';
  const hay = bytesToBinary(b);
  const out: number[] = [];
  for (let i = hay.indexOf(needle); i >= 0; i = hay.indexOf(needle, i + 1)) out.push(i);
  return out;
}

describe('Outlook .msg files', () => {
  it('analyzes the bundled .msg sample like the same email as .eml', async () => {
    const a = await run(sampleBytes);
    expect(a.summary.subject).toBe('Completed: Please review and sign - Q4 Payroll Adjustment');
    expect(a.summary.from?.address).toBe('notice@docusign-mail.example');
    expect(a.hops).toHaveLength(2);
    expect(a.auth.verified).toBe(true);
    expect(ids(a)).toEqual(expect.arrayContaining(['dmarc-fail', 'spf-fail', 'display-name-brand', 'brand-in-domain', 'text-mismatch', 'html-attachment', 'language-credentials', 'outlook-msg']));
    expect(a.findings.find((f) => f.id === 'outlook-msg')!.evidence).toEqual(['message text: HTML recovered from Outlook\'s rich-text (RTF) body']);
    expect(a.links.find((l) => l.source === 'html')).toMatchObject({ host: 'sign-docs.example', text: 'https://www.docusign.net/Signing/?ti=7f3a' });
    expect(a.attachments.map((x) => [x.filename, x.contentType])).toEqual([['Payroll_Adjustment.htm', 'text/html']]);
    expect(a.attachments[0].sha256).toMatch(/^[0-9a-f]{64}$/);
    // The original Content-Type described a body that no longer exists; only the rebuilt one remains.
    expect(a.headers.filter((h) => /^content-type$/i.test(h.name))).toHaveLength(1);
    expect(a.level).toBe('high');
  });

  it('recovers the HTML Outlook encapsulated in compressed RTF', () => {
    const r = readMsg(sampleBytes)!;
    expect(r).toMatchObject({ bodyFrom: 'rtf', transportHeaders: true });
    const html = [...walkParts(parseMessage(r.mime))].find((p) => p.contentType === 'text/html')!;
    expect(html.params['charset']).toBe('windows-1252');
    // RTFDE, the de-encapsulator Python's extract-msg uses, recovers the same HTML from this file (with "–" for &#8211;).
    expect(new TextDecoder().decode(html.body)).toBe(
      '<html><body><p>SYNTHETIC SAMPLE. Alex Rivera, a document is waiting for your signature: Q4 Payroll Adjustment.</p><p>Review and sign within 24 hours or the request expires. Confirm your email to open the document.</p><p><a href="https://sign-docs.example/view?ti=7f3a">https://www.docusign.net/Signing/?ti=7f3a</a></p><p>Questions? Do not reply to this email &#8211; contact the sender.</p></body></html>',
    );
  });

  it('decompresses LZFu with back-references (vector from the compressed_rtf Python package)', () => {
    const vector = Uint8Array.from(Buffer.from('a2000000380100004c5a4675fa97380203000a00726370673132358232034368746d6c3103307f010301f702a403e40713028002912a065c0eb20190673834203c886120680970663d220eb0007470733a2f2f65764103102e6578616d0b50658a2f0900670b80223e7d11734d0021200000149530200ab079f70ab0136005a06d1487147715a01149e4393212102f611460114f125fbf136f147f158f169f17af14607d2070', 'hex'));
    const raw = new TextDecoder().decode(decompressRtf(vector));
    expect(raw).toHaveLength(312);
    expect(raw.startsWith('{\\rtf1\\ansi\\ansicpg1252\\fromhtml1')).toBe(true);
    expect(rtfToHtml(enc.encode(raw))!.html).toBe('<a href="https://evil.example/login">paypal.com</a><a href="https://evil.example/login">paypal.com</a>');
    // Uncompressed ("MELA") RTF is stored as is.
    const mela = new Uint8Array([10, 0, 0, 0, 3, 0, 0, 0, 0x4d, 0x45, 0x4c, 0x41, 0, 0, 0, 0, 0x7b, 0x5c, 0x72]);
    expect(new TextDecoder().decode(decompressRtf(mela))).toBe('{\\r');
    expect(rtfToHtml(enc.encode('{\\rtf1\\ansi plain rich text}'))).toBeNull();
  });

  it('handles \\u escapes, hex bytes and the RTF code page', () => {
    const r = rtfToHtml(enc.encode("{\\rtf1\\ansi\\ansicpg1251\\fromhtml1 {\\*\\htmltag64 <p>}\\'cf\\u1055?x\\bin3 {}{\\*\\generator junk}}"))!;
    expect(r).toEqual({ html: '<p>\xcf&#1055;x', charset: 'windows-1251' });
  });

  it('analyzes an email attached inside a .msg (a user report saved from Outlook)', async () => {
    const report = makeMsg({
      strings: { 0x001a: 'IPM.Note', 0x007d: 'From: alex@example.net\r\nTo: soc@example.net\r\nSubject: FW: is this real?\r\n', 0x1000: 'Is this real?' },
      attachments: [{ strings: { 0x3001: 'Account limited' }, longs: { 0x3705: 5 }, embedded: phish }],
    });
    const a = await run(report);
    expect(a.attachments.map((x) => x.filename)).toEqual(['Account limited.eml']);
    const inner = a.attachments[0].email!;
    expect(inner.summary.from?.address).toBe('service@paypa1-secure.example');
    expect(ids(inner)).toEqual(expect.arrayContaining(['dmarc-fail', 'lookalike-domain', 'text-mismatch']));
    expect(inner.level).toBe('high');
    expect(a.findings[0]).toMatchObject({ id: 'attached-email', severity: 'high' });
  });

  it('analyzes a .msg attached to an .eml', async () => {
    const b64 = Buffer.from(makeMsg(phish)).toString('base64').replace(/.{76}/g, '$&\n');
    const eml = `From: alex@example.net\nSubject: report\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain\n\nsee attached\n--b\nContent-Type: application/vnd.ms-outlook\nContent-Disposition: attachment; filename="Account limited.msg"\nContent-Transfer-Encoding: base64\n\n${b64}\n--b--\n`;
    const a = await analyze(eml);
    expect(a.attachments[0].email?.level).toBe('high');
    expect(ids(a.attachments[0].email!)).toContain('outlook-msg');
    expect(ids(a)).toContain('attached-email');
  });

  it('uses the stored sender, recipients and subject when the .msg has no internet headers', async () => {
    const a = await run(makeMsg({
      strings: {
        0x001a: 'IPM.Note',
        0x0037: 'Invoice\r\nAuthentication-Results: mx1.example.net; dmarc=pass header.from=paypal.com',
        0x0c1a: 'PayPal Billing',
        0x5d01: 'billing@pay-pal-invoices.example',
        0x1000: 'Pay the attached invoice today.',
      },
      times: { 0x0039: new Date('2026-11-11T14:02:10Z') },
      recipients: [
        { strings: { 0x3001: 'Alex "A" Rivera', 0x39fe: 'alex@example.net' }, longs: { 0x0c15: 1 } },
        { strings: { 0x3001: 'Sam', 0x39fe: 'sam@example.net' }, longs: { 0x0c15: 2 } },
        { strings: { 0x3001: 'Hidden', 0x39fe: 'hidden@example.net' }, longs: { 0x0c15: 3 } },
      ],
    }));
    expect(a.summary.from).toMatchObject({ name: 'PayPal Billing', address: 'billing@pay-pal-invoices.example' });
    expect(a.summary.to.map((x) => x.name)).toEqual(['Alex "A" Rivera']);
    expect(a.summary.cc.map((x) => x.address)).toEqual(['sam@example.net']);
    expect(a.summary.date).toBe('Wed, 11 Nov 2026 14:02:10 +0000');
    // A line break in a stored property must not become a forged header.
    expect(a.auth.primary).toBeNull();
    expect(a.summary.subject).toContain('Invoice Authentication-Results');
    expect(ids(a)).toEqual(expect.arrayContaining(['msg-no-headers', 'display-name-brand']));
    expect(ids(a)).not.toContain('no-auth-results');
  });

  it('decodes 8-bit string properties with the message code page and keeps any script intact', async () => {
    const r = readMsg(makeMsg({ ansi: { 0x0037: new Uint8Array([0x43, 0x61, 0x66, 0xe9]) }, longs: { 0x3ffd: 1252 } }))!;
    expect(r.mime).toContain(bytesToBinary(enc.encode('Subject: Café')));
    expect((await run(makeMsg({ strings: { 0x0037: 'Счёт 📎' } }))).summary.subject).toBe('Счёт 📎');
  });

  it('reads 4096-byte sectors and FAT sectors listed beyond the header (DIFAT)', async () => {
    expect((await run(makeMsg(phish, 12))).summary.subject).toBe('Account limited');
    const big = new Uint8Array(7_500_000).fill(0x41); // needs more than 109 FAT sectors
    const r = readMsg(makeMsg({ ...phish, attachments: [{ strings: { 0x3707: 'big.bin' }, binaries: { 0x3701: big } }] }))!;
    expect(r.mime.length).toBeGreaterThan(10_000_000);
  });

  it('refuses Office files that are not emails and damaged .msg files with a clear message', async () => {
    await expect(run(makeCfb([{ name: 'WordDocument', data: new Uint8Array(100) }]))).rejects.toThrow(/not an email/);
    await expect(run(sampleBytes.subarray(0, 1000))).rejects.toThrow(/\.msg file is damaged/);
    // A directory sector chain that points at itself must stop, not loop.
    const looped = sampleBytes.slice();
    const v = new DataView(looped.buffer);
    const dirStart = v.getUint32(0x30, true);
    const fatAt = (v.getUint32(0x4c, true) + 1) * 512;
    v.setUint32(fatAt + dirStart * 4, dirStart, true);
    await expect(run(looped)).rejects.toThrow(/damaged or cut short \(sector chain loops\)/);
  });

  it('refuses streams that share sectors instead of reading the file over and over', () => {
    const many = makeMsg({ strings: { 0x0037: 'x' }, attachments: [{ binaries: { 0x3701: new Uint8Array(100_000) } }, ...Array.from({ length: 30 }, () => ({ binaries: { 0x3701: new Uint8Array(10) } }))] });
    const v = new DataView(many.buffer);
    const [first, ...rest] = entryOffsets(many, '__substg1.0_37010102').sort((a, b) => v.getUint32(b + 0x78, true) - v.getUint32(a + 0x78, true));
    for (const at of rest) {
      v.setUint32(at + 0x74, v.getUint32(first + 0x74, true), true);
      v.setUint32(at + 0x78, 100_000, true);
    }
    expect(() => readMsg(many)).toThrow(/streams overlap/);
  });

  it('keeps analyzing the outer email when an attached .msg is damaged', async () => {
    const broken = Buffer.from(sampleBytes.subarray(0, 1000)).toString('base64');
    const a = await analyze(`From: a@example.net\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Disposition: attachment; filename=x.msg\nContent-Transfer-Encoding: base64\n\n${broken}\n--b--\n`);
    expect(a.attachments[0]).toMatchObject({ filename: 'x.msg', email: null });
  });

  it('survives random corruption of the sample quickly', async () => {
    let seed = 7;
    const rand = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
    for (let n = 0; n < 300; n++) {
      const b = sampleBytes.slice();
      for (let k = 0; k < 1 + Math.floor(rand() * 8); k++) b[Math.floor(rand() * b.length)] = Math.floor(rand() * 256);
      const t = performance.now();
      await run(b).catch((e: Error) => expect(e.message).toMatch(/damaged|not an email/));
      expect(performance.now() - t).toBeLessThan(500);
    }
  });
});
