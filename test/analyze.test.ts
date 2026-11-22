import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { analyze } from '../src/core/analyze';
import { bytesToBinary, textToBinary } from '../src/core/encoding';

const sample = (name: string) => analyze(bytesToBinary(new Uint8Array(readFileSync(new URL(`../samples/${name}`, import.meta.url)))));
const ids = (a: Awaited<ReturnType<typeof analyze>>) => a.findings.map((f) => f.id).sort();

describe('end-to-end on the bundled samples', () => {
  it('rates the legitimate newsletter low with nothing to explain', async () => {
    const a = await sample('03-newsletter-legit.eml');
    expect(a.score).toBe(0);
    expect(a.level).toBe('low');
    expect(a.summary.subject).toBe('November in the garden 🌱');
    expect(a.reassurances[0]).toContain('DMARC passed');
    expect(a.hops).toHaveLength(2);
  });

  it('explains the PayPal look-alike', async () => {
    const a = await sample('01-paypal-lookalike.eml');
    expect(a.level).toBe('high');
    expect(ids(a)).toEqual(expect.arrayContaining(['display-name-brand', 'lookalike-domain', 'text-mismatch', 'reply-to-mismatch', 'idn-domain', 'spf-softfail', 'language-credentials']));
    const safelink = a.links.find((l) => l.unwrappedVia.length)!;
    expect(safelink.host).toBe('xn--pypal-4ve.example');
    expect(a.hops.map((h) => h.delaySeconds)).toEqual([null, 499, 2]);
  });

  it('finds the macro document and the HTML attachment with hashes', async () => {
    const a = await sample('02-invoice-macro.eml');
    expect(a.attachments.map((x) => x.filename)).toEqual(['Invoice_88231.docm', 'Remittance_Advice.pdf.html']);
    expect(a.attachments.every((x) => /^[0-9a-f]{64}$/.test(x.sha256))).toBe(true);
    expect(ids(a)).toEqual(expect.arrayContaining(['office-macro', 'double-extension', 'html-attachment', 'reply-to-mismatch']));
    // Passing authentication is reported as reassurance but does not cancel the risk.
    expect(a.reassurances[0]).toContain('DMARC passed');
    expect(a.level).toBe('high');
  });

  it('catches the CEO gift-card request', async () => {
    const a = await sample('04-ceo-gift-cards.eml');
    expect(ids(a)).toEqual(expect.arrayContaining(['display-name-address', 'reply-to-mismatch', 'language-money', 'time-travel']));
    expect(a.nextSteps.join(' ')).toContain('by phone');
  });

  it('catches every link trick in the parcel sample', async () => {
    const a = await sample('05-parcel-redelivery.eml');
    expect(ids(a)).toEqual(expect.arrayContaining(['dmarc-fail', 'compauth-fail', 'userinfo', 'text-mismatch', 'data-uri', 'ip-host', 'shortener', 'risky-download', 'brand-in-domain']));
    expect(a.score).toBe(100);
  });

  it('analyzes an email forwarded as an attachment on its own', async () => {
    const a = await sample('06-user-report-forwarded.eml');
    const inner = a.attachments[0].email!;
    expect(inner.summary.from?.address).toBe('service@paypa1-secure.example');
    expect(inner.level).toBe('high');
    expect(a.findings[0].id).toBe('attached-email');
  });

  it('never produces findings without an explanation', async () => {
    for (const name of ['01-paypal-lookalike.eml', '02-invoice-macro.eml', '04-ceo-gift-cards.eml', '05-parcel-redelivery.eml']) {
      for (const f of (await sample(name)).findings) {
        expect(f.title.length).toBeGreaterThan(5);
        expect(f.explanation.length).toBeGreaterThan(20);
      }
    }
  });

  it('checks every distinct link text behind the same URL', async () => {
    const a = await analyze('Content-Type: text/html\n\n<a href="https://evil.example/">Home</a><a href="https://evil.example/">paypal.com</a>');
    expect(a.links).toHaveLength(2);
    expect(a.findings.map((f) => f.id)).toContain('text-mismatch');
  });

  it('gives no reassurance for Authentication-Results it cannot tie to a receiving server', async () => {
    const a = await analyze('From: ceo@company.example\nAuthentication-Results: forged; dmarc=pass header.from=company.example\n\nHi');
    expect(a.auth.verified).toBe(false);
    expect(a.reassurances.join(' ')).not.toContain('DMARC');
    expect(a.findings.map((f) => f.id)).toContain('auth-unverified');
  });

  it('analyzes pasted body text that has no headers instead of dropping it', async () => {
    const a = await analyze('Dear customer,\nPlease verify your account within 24 hours: https://paypa1-login.example/x\n\nThanks');
    expect(a.headers).toEqual([]);
    expect(a.bodyText).toContain('Dear customer');
    expect(a.links.map((l) => l.host)).toEqual(['paypa1-login.example']);
    expect(a.findings.map((f) => f.id)).toEqual(expect.arrayContaining(['no-headers', 'lookalike-domain', 'language-credentials']));
    expect(a.findings.map((f) => f.id)).not.toContain('no-auth-results');
  });

  it('does not mistake surnames and everyday words in a display name for a brand', async () => {
    const ids = async (from: string) => (await analyze(`From: ${from}\nSubject: hi\n\nhi`)).findings.map((f) => f.id);
    expect(await ids('Jane Norton <jane@company.example>')).not.toContain('display-name-brand');
    expect(await ids('Weekly Market Outlook <news@bank.example>')).not.toContain('display-name-brand');
    expect(await ids('Norton 360 <billing@renewals.example>')).toContain('display-name-brand');
    expect(await ids('Microsoft Outlook <no-reply@mail-team.example>')).toContain('display-name-brand');
  });

  it('sees a brand name through invisible, full-width and look-alike characters', async () => {
    // Each displays as the brand in a mail client but slipped past the brand check.
    const ids = async (from: string) => (await analyze(textToBinary(`From: ${from}\nSubject: hi\n\nhi`))).findings.map((f) => f.id);
    for (const name of ['Pay​Pal', 'Pay­Pal', 'Pay‍Pal Support', 'PаyPal', 'ＰａｙＰａｌ', 'Mіcrosoft']) {
      expect(await ids(`"${name}" <x@evil.example>`), name).toContain('display-name-brand');
    }
    expect(await ids('"service@pay​pal.com" <x@evil.example>')).toContain('display-name-address');
    expect(await ids('"IT Help​desk" <it@gmail.com>')).toContain('freemail-official');
  });

  it('rates two attached emails by the riskier one', async () => {
    const inner = (html: string) => `Content-Type: message/rfc822\n\nFrom: a@b.example\nContent-Type: text/html\n\n${html}\n`;
    const a = await analyze(['Content-Type: multipart/mixed; boundary=b', '', '--b',
      inner('<a href="https://evil.example/">paypal.com</a>'), '--b',
      inner('<a href="https://evil.example/">paypal.com</a><a href="javascript:x()">Go</a><a href="data:text/html,x">Open</a>'), '--b--', ''].join('\n'));
    expect(a.attachments.map((x) => x.email?.level)).toEqual(['suspicious', 'high']);
    expect(a.findings.find((f) => f.id === 'attached-email')).toMatchObject({ severity: 'high', points: 25 });
  });

  it('analyzes an attached .eml sent as application/octet-stream', async () => {
    // Some mail apps and ticket systems attach a reported email this way; it scored 0 with no inner analysis.
    const phish = readFileSync(new URL('../samples/01-paypal-lookalike.eml', import.meta.url)).toString('base64');
    const a = await analyze(['From: sam@corp.example', 'Subject: Fwd: phish?', 'Content-Type: multipart/mixed; boundary=b', '', '--b',
      'Content-Type: application/octet-stream', 'Content-Disposition: attachment; filename="phish.eml"', 'Content-Transfer-Encoding: base64', '', phish, '--b--', ''].join('\n'));
    expect(a.attachments[0].email?.level).toBe('high');
    expect(ids(a)).toContain('attached-email');
    // Any other octet-stream attachment is still just a file.
    const other = await analyze(['Content-Type: multipart/mixed; boundary=b', '', '--b', 'Content-Type: application/octet-stream',
      'Content-Disposition: attachment; filename="notes.bin"', '', 'From: a@b.example', '', 'x', '--b--', ''].join('\n'));
    expect(other.attachments[0].email).toBeNull();
  });

  it('handles empty and garbage input without throwing', async () => {
    expect((await analyze('')).score).toBe(0);
    const junk = await analyze('\x00\xff random bytes \n\n\n--x--');
    expect(junk.level).toBe('low');
  });
  it('refuses a PDF, image, archive or program instead of calling it low risk', async () => {
    // Users drop the suspicious attachment itself; "No strong warning signs found" for an invoice.pdf is false comfort.
    await expect(analyze('%PDF-1.7\n1 0 obj\n<< /URI (https://evil.example/) >>\n')).rejects.toThrow('looks like a PDF, not an email');
    await expect(analyze('\x89PNG\r\n\x1a\n\0\0\0\rIHDR')).rejects.toThrow('PNG image');
    await expect(analyze('PK\x03\x04\x14\0\0\0')).rejects.toThrow('ZIP archive');
    await expect(analyze('MZ\x90\0\x03\0\0\0')).rejects.toThrow('Windows program');
    // Text that happens to start like a file signature is still analyzed.
    expect((await analyze('MZ Bank: verify your account today')).findings.map((f) => f.id)).toContain('language-credentials');
    expect((await analyze('<html><body><a href="https://evil.example/">Sign in</a></body></html>')).links).toHaveLength(1);
  });
  it('reads files with bare CR or doubled CR line endings like the original', async () => {
    // CR-only scored 0 and \r\r\n (CRLF re-saved in text mode on Windows) lost the links and an attachment.
    const raw = bytesToBinary(new Uint8Array(readFileSync(new URL('../samples/02-invoice-macro.eml', import.meta.url))));
    const want = await analyze(raw);
    for (const eol of ['\r', '\r\r\n']) {
      const a = await analyze(raw.replace(/\r?\n/g, eol));
      expect([a.score, ids(a), a.attachments.map((x) => x.sha256)]).toEqual([want.score, ids(want), want.attachments.map((x) => x.sha256)]);
    }
    // A stray CR in a well-formed message (here inside an unencoded attachment) leaves its bytes alone.
    const stray = await analyze('From: a@b.example\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: application/octet-stream; name=a.bin\r\n\r\nx\ry\r\n--b--\r\n');
    expect(stray.attachments[0].sha256).toBe('029adb4e81fda56ca4173173940e5c2015e946d72ea36dc52a16db3cc3b1c810'); // SHA-256 of "x\ry"
    const t = performance.now();
    await analyze(`From: a@b.example\r\r\n${'\r'.repeat(300000)}x${'\r\r\n'.repeat(100000)}`);
    expect(performance.now() - t).toBeLessThan(500);
  });
  it('reads headers saved as UTF-16 (Notepad "Unicode")', async () => {
    // Was read byte by byte: no headers, score 0, "No strong warning signs found".
    const text = readFileSync(new URL('../samples/01-paypal-lookalike.eml', import.meta.url), 'utf8').replace(/\n/g, '\r\n');
    const want = await sample('01-paypal-lookalike.eml');
    for (const [bom, enc] of [[[0xff, 0xfe], 'utf16le'], [[0xfe, 0xff], 'utf16be']] as const) {
      const body = Buffer.from(text, 'utf16le');
      if (enc === 'utf16be') body.swap16();
      const a = await analyze(bytesToBinary(new Uint8Array([...bom, ...body])));
      expect([a.score, ids(a)]).toEqual([want.score, ids(want)]);
    }
  });
  it('reads a file saved with a UTF-8 byte order mark', async () => {
    // Windows editors add one; it made the first header "﻿From" and hid the sender.
    const a = await analyze('\xEF\xBB\xBFFrom: "PayPal" <service@paypa1.example>\nSubject: hi\n\nhello');
    expect(a.summary.from?.domain).toBe('paypa1.example');
    expect(a.findings.map((f) => f.id)).toContain('lookalike-domain');
  });
  it('keeps thousands of distinct link findings linear', async () => {
    const t = performance.now();
    const a = await analyze('Content-Type: text/html\n\n' + Array.from({ length: 40000 }, (_, i) => `<a href="data:text/html,${i}">x</a>`).join(''));
    expect(a.findings.find((f) => f.id === 'data-uri')?.evidence).toHaveLength(40000);
    expect(performance.now() - t).toBeLessThan(1500); // was about 8 s with evidence.includes()
  });
  it('checks links made relative by a <base href> (baseStriker)', async () => {
    const a = await analyze('From: a@b.example\nContent-Type: text/html\n\n<base href="https://paypa1-secure.top/"><a href="signin">https://www.paypal.com/signin</a>');
    expect(a.findings.map((f) => f.id)).toEqual(expect.arrayContaining(['text-mismatch', 'lookalike-domain']));
  });
  it('still analyzes an email whose sender domain has a 200,000-character xn-- label', async () => {
    const a = await analyze(`From: x@xn--${'a'.repeat(200000)}-ba.example\nSubject: verify your account\n\nhi`);
    expect(a.findings.some((f) => f.id === 'language-credentials')).toBe(true);
  });
});
