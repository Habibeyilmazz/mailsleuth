import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { analyze } from '../src/core/analyze';
import { toMarkdown } from '../src/core/report';
import { bytesToBinary, textToBinary } from '../src/core/encoding';
import { makePdf } from '../scripts/pdf.ts';
import { makeZip } from '../scripts/zip.ts';

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

  it('finds the look-alike link inside the PDF of an email that passes every check', async () => {
    const a = await sample('08-pdf-link-lure.eml');
    expect(ids(a)).toEqual(['attachment-links', 'lookalike-domain']);
    expect(a.level).toBe('suspicious');
    expect(a.links).toMatchObject([{ source: 'pdf', attachment: 'Q4_Rate_Sheet.pdf', host: 'rnicrosoft-online.example', text: null }]);
    expect(a.findings.find((f) => f.id === 'lookalike-domain')!.evidence[0]).toMatch(/^Link in Q4_Rate_Sheet\.pdf: /);
    expect(a.reassurances.join(' ')).not.toContain('no links');
  });

  it('sees the remote template and the mailto trick in the calm contract email', async () => {
    const a = await sample('09-contract-remote-template.eml');
    expect(ids(a)).toEqual(['attachment-links', 'ip-host', 'mailto-mismatch', 'office-remote-content']);
    expect(a.score).toBe(49);
    expect(a.links).toMatchObject([{ source: 'office', attachment: 'Supply_Contract_2027.docx', host: '198.51.100.23' }]);
    expect(a.nextSteps.join(' ')).toContain('Do not open the attachment');
  });

  it('reads the sign-in page inside the voicemail ZIP', async () => {
    const a = await sample('10-voicemail-zip.eml');
    expect(ids(a)).toEqual(['archive-risky-content', 'attachment-links', 'ip-host', 'lookalike-domain']);
    expect(a.score).toBe(62);
    const inside = 'VM_0042.zip › VM_0042/Play_Voicemail.html';
    expect(a.links.map((l) => [l.host, l.attachment])).toEqual([['login.rnicrosoftonline-voice.example', inside], ['198.51.100.61', inside]]);
    expect(a.attachments[0].zipHashes.map((z) => z.name)).toEqual(['VM_0042/Play_Voicemail.html']);
    expect(a.attachments[0].zipEntries).toEqual(['VM_0042/Play_Voicemail.html']); // the folder entry is not a file
  });

  it('lists the form target of an HTML attachment as a link of that attachment', async () => {
    const a = await sample('02-invoice-macro.eml');
    expect(a.links.filter((l) => l.attachment)).toMatchObject([{ finalUrl: 'https://collect.invalid/submit', text: '(form submit)', attachment: 'Remittance_Advice.pdf.html' }]);
  });

  it('reads script redirects and refreshes in HTML attachments, keeps the body entry for a shared link, skips XML namespaces', async () => {
    const page = `<svg xmlns="http://www.w3.org/2000/svg"><meta http-equiv="refresh" content="0;url=https://refresh.example/x"><script>location.href="https://evil.example/?e="+atob("eA==")</script><a xlink:href="https://body.example/">x</a></svg>`;
    const a = await analyze(`From: a@b.example\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain\n\nsee https://body.example/\n--b\nContent-Type: image/svg+xml\nContent-Disposition: attachment; filename=scan.svg\n\n${page}\n--b--\n`);
    expect(a.links.map((l) => [l.finalUrl, l.attachment])).toEqual([
      ['https://body.example/', null],
      ['https://body.example/', 'scan.svg'], // different visible text, so checked again
      ['https://refresh.example/x', 'scan.svg'],
      ['https://evil.example/?e=', 'scan.svg'],
    ]);
  });

  it('adds PDF actions to the attachment and its links to the link checks', async () => {
    const pdf = makePdf(['<< /Type /Catalog /OpenAction << /S /JavaScript /JS (app.launchURL("x")) >> >>'], ['<< /S /URI /URI (https://bit.ly/x) >>']);
    const eml = `From: a@b.example\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain\n\nhi\n--b\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename=doc.pdf\nContent-Transfer-Encoding: base64\n\n${Buffer.from(pdf).toString('base64')}\n--b--\n`;
    const a = await analyze(eml);
    expect(a.attachments[0].issues.map((i) => i.id)).toEqual(['pdf-javascript']);
    expect(ids(a)).toEqual(['attachment-links', 'no-auth-results', 'pdf-javascript', 'shortener']);
    expect(a.findings.find((f) => f.id === 'shortener')!.evidence).toEqual(['in doc.pdf: bit.ly is a link shortener: the real destination is hidden until you click']);
    expect(a.nextSteps.join(' ')).toContain('Do not open the attachment');
  });

  it('reads external links and remote templates from Office attachments, stored or deflated', async () => {
    const R = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/';
    const rel = (type: string, target: string, ext = true) => `<Relationship Id="r${type}" Type="${R}${type}" Target="${target}"${ext ? ' TargetMode="External"' : ''}/>`;
    const documentRels = `<Relationships>${rel('styles', 'styles.xml', false)}${rel('hyperlink', 'https://rnicrosoft-online.example/doc?a=1&amp;b=2')}${rel('hyperlink', '\\\\files.example\\share')}</Relationships>`;
    const settingsRels = `<Relationships>${rel('attachedTemplate', 'file:///C:\\Users\\pat\\Normal.dotm')}${rel('attachedTemplate', 'http://203.0.113.9/t.dotm')}</Relationships>`;
    const deflate = async (t: string) => new Uint8Array(await new Response(new Blob([t]).stream().pipeThrough(new CompressionStream('deflate-raw'))).arrayBuffer());
    const docx = makeZip([
      { name: '[Content_Types].xml', data: '<Types/>' },
      { name: 'word/document.xml', data: '<w:document/>' },
      { name: 'word/_rels/document.xml.rels', data: documentRels, deflated: await deflate(documentRels) },
      { name: 'word/_rels/settings.xml.rels', data: settingsRels },
    ]);
    const eml = `From: a@b.example\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain\n\nhi\n--b\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename=Contract.docx\nContent-Transfer-Encoding: base64\n\n${Buffer.from(docx).toString('base64')}\n--b--\n`;
    const a = await analyze(eml);
    expect(a.links.map((l) => [l.href, l.source, l.attachment])).toEqual([
      ['https://rnicrosoft-online.example/doc?a=1&b=2', 'office', 'Contract.docx'],
      ['\\\\files.example\\share', 'office', 'Contract.docx'],
      ['http://203.0.113.9/t.dotm', 'office', 'Contract.docx'],
    ]);
    expect(ids(a)).toEqual(expect.arrayContaining(['office-remote-content', 'lookalike-domain', 'local-link', 'ip-host', 'attachment-links']));
    expect(a.findings.find((f) => f.id === 'office-remote-content')!.evidence).toEqual(['Contract.docx: the document loads a template from 203.0.113.9 when opened (see Links)']);
    // An ordinary document with only internal parts and a template on the author's disk: nothing to report.
    const plain = makeZip([{ name: '[Content_Types].xml', data: '<Types/>' }, { name: 'word/_rels/settings.xml.rels', data: `<Relationships>${rel('attachedTemplate', 'file:///C:\\T\\Normal.dotm')}</Relationships>` }]);
    const b = await analyze(eml.replace(Buffer.from(docx).toString('base64'), Buffer.from(plain).toString('base64')));
    expect(b.links).toEqual([]);
    expect(b.attachments[0].issues).toEqual([]);
  });

  it('checks links and content of the files inside an attached ZIP, one level deep', async () => {
    const page = '<html><form action="https://rnicrosoft-online.example/login.php"><input type=password></form></html>';
    const deflate = async (t: string) => new Uint8Array(await new Response(new Blob([t]).stream().pipeThrough(new CompressionStream('deflate-raw'))).arrayBuffer());
    const docm = makeZip([{ name: '[Content_Types].xml', data: '<Types/>' }, { name: 'word/vbaProject.bin', data: 'x' }]);
    const inner = makeZip([{ name: 'deep.html', data: '<a href="https://deep.example/">x</a>' }]);
    const statement = makePdf([], ['<< /S /URI /URI (https://bit.ly/x) >>']);
    const zip = makeZip([
      { name: 'Payment/', data: '' },
      { name: 'Payment/Remittance.html', data: page, deflated: await deflate(page) },
      { name: 'Payment/Statement.pdf', data: statement },
      { name: 'Payment/Report.docx', data: docm },
      { name: 'Payment/more.zip', data: inner },
      { name: 'Payment/locked.pdf', data: '%PDF-1.7 /URI (https://hidden.example/)', encrypted: true },
    ]);
    const b64 = Buffer.from(zip).toString('base64');
    const eml = `From: a@b.example\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain\n\nhi\n--b\nContent-Type: application/zip\nContent-Disposition: attachment; filename=Remittance.zip\nContent-Transfer-Encoding: base64\n\n${b64}\n--b--\n`;
    const a = await analyze(eml);
    expect(a.links.map((l) => [l.href, l.source, l.attachment])).toEqual([
      ['https://rnicrosoft-online.example/login.php', 'html', 'Remittance.zip › Payment/Remittance.html'],
      ['https://bit.ly/x', 'pdf', 'Remittance.zip › Payment/Statement.pdf'],
    ]);
    // The HTML entry is already named by archive-risky-content; the macro is only visible by opening the inner document.
    expect(a.attachments[0].issues.map((i) => i.id)).toEqual(['encrypted-archive', 'archive-risky-content', 'office-macro', 'archive-risky-content']);
    expect(a.attachments[0].issues[2].detail).toMatch(/^in Payment\/Report\.docx: the document contains a VBA macro/);
    expect(a.attachments[0].issues[3].detail).toBe('in Payment/more.zip: archive contains deep.html');
    expect(ids(a)).toEqual(['archive-risky-content', 'attachment-links', 'encrypted-archive', 'lookalike-domain', 'no-auth-results', 'office-macro', 'shortener']);
    expect(a.findings.find((f) => f.id === 'attachment-links')!.evidence).toEqual(['Remittance.zip › Payment/Remittance.html: 1 link', 'Remittance.zip › Payment/Statement.pdf: 1 link']);
    // Hashes of the unpacked files, for lookups: the archive's own hash changes with every copy sent.
    expect(a.attachments[0].zipHashes.map((z) => z.name)).toEqual(['Payment/Remittance.html', 'Payment/Statement.pdf', 'Payment/Report.docx', 'Payment/more.zip']);
    const pdfHash = createHash('sha256').update(statement).digest('hex');
    expect(a.attachments[0].zipHashes[1].sha256).toBe(pdfHash);
    const md = toMarkdown(a);
    expect(md).toContain(`  - SHA-256 of \`Payment/Statement.pdf\` inside: \`${pdfHash}\``);
    expect(md).toContain(`\nsha256:${pdfHash}\n`);
    expect(md).toContain('inside the attachment `Remittance.zip › Payment/Remittance.html`');
  });

  it('never produces findings without an explanation', async () => {
    for (const name of ['01-paypal-lookalike.eml', '02-invoice-macro.eml', '04-ceo-gift-cards.eml', '05-parcel-redelivery.eml', '08-pdf-link-lure.eml', '09-contract-remote-template.eml', '10-voicemail-zip.eml']) {
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

  it('treats a uuencoded file in the message text as an attachment', async () => {
    // Encoded by Python's binascii.b2a_uu: 286 bytes starting with "MZ".
    const uu = 'begin 644 invoice.pdf.exe\nM35J0```!`@,$!08\'"`D*"PP-#@\\0$1(3%!46%Q@9&AL<\'1X?("$B(R0E)B<H\nM*2HK+"TN+S`Q,C,T-38W.#DZ.SP]/C]`04)#1$5&1TA)2DM,34Y/4%%24U15\nM5E=865I;7%U>7V!A8F-D969G:&EJ:VQM;F]P<7)S=\'5V=WAY>GM\\?7Y_@(&"\nM@X2%AH>(B8J+C(V.CY"1DI.4E9:7F)F:FYR=GI^@H:*CI*6FIZBIJJNLK:ZO\nML+&RL[2UMK>XN;J[O+V^O\\#!PL/$Q<;\'R,G*R\\S-SL_0T=+3U-76U]C9VMO<\nMW=[?X.\'BX^3EYN?HZ>KK[.WN[_#Q\\O/T]?;W^/GZ^_S]_O]P;&%C96AO;&1E\n0<BP@;F]T(&$@<\')O9W)A;0``\n`\nend\n';
    const a = await analyze(`From: billing@vendor.example\nSubject: Invoice\n\nPlease see the invoice below.\n\n${uu.replace(/\n/g, '\r\n')}\nThanks`);
    expect(a.attachments.map((x) => [x.filename, x.size, x.sha256])).toEqual([['invoice.pdf.exe', 286, '00e86c4fefbcecef2c9a6a8a3d71c1d6192d996eb9d18245ac95a541ba31386b']]);
    expect(ids(a)).toEqual(expect.arrayContaining(['double-extension', 'executable', 'uuencoded']));
    // Prose that merely starts with "begin 644" is not a file.
    const prose = await analyze('From: a@b.example\n\nbegin 644 is the file mode we use\nHello there, see you at the meeting.\nend');
    expect(prose.attachments).toEqual([]);
  });

  it('flags a mailto: link whose text shows an address at another domain', async () => {
    const html = (a: string) => analyze(`From: ceo@company.example\nContent-Type: text/html\n\n${a}`);
    const bad = await html('Write to <a href="mailto:ceo.desk%40quick-reply.example?subject=Wire">ceo@company.example</a>');
    const f = bad.findings.find((x) => x.id === 'mailto-mismatch');
    expect(f?.points).toBe(12);
    expect(f?.evidence).toEqual(['link text shows ceo@company.example but writes to ceo.desk@quick-reply.example']);
    // Same organisation, plain name text, or no address in the text: nothing to flag.
    for (const ok of [
      '<a href="mailto:Sales@Mail.Company.example">sales@company.example</a>',
      '<a href="mailto:x@quick-reply.example">Contact us</a>',
      '<a href="mailto:ceo@company.example,x@company.example">ceo@company.example</a>',
    ]) expect((await html(ok)).findings.map((x) => x.id)).not.toContain('mailto-mismatch');
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

  it('sees a capital I standing in for a lower-case l in a brand name', async () => {
    // "PaypaI" and "AppIe" look the same as the brand in most sans-serif fonts, and scored 0.
    const ids = async (from: string) => (await analyze(textToBinary(`From: ${from}\nSubject: hi\n\nhi`))).findings.map((f) => f.id);
    for (const name of ['PaypaI', 'AppIe Support', 'GoogIe']) expect(await ids(`"${name}" <x@evil.example>`), name).toContain('display-name-brand');
    // Not when the capital I follows another capital or starts a word: DHI is not DHL, "IT" is not "lt".
    for (const name of ['DHI Group', 'IT Desk']) expect(await ids(`"${name}" <x@evil.example>`), name).not.toContain('display-name-brand');
    expect(await ids('LinkedIn <x@evil.example>')).toContain('display-name-brand');
  });

  it('flags a message with more than one From address', async () => {
    // Mail apps and filters can disagree on which one is the sender; only the first was looked at, score 0.
    const run = (headers: string) => analyze(textToBinary(`${headers}\nSubject: hi\n\nhi`));
    const two = await run('From: a@paypal.com\nFrom: b@evil.example');
    expect(two.findings.find((f) => f.id === 'multiple-from')).toMatchObject({ severity: 'medium', evidence: ['a@paypal.com, b@evil.example'] });
    expect((await run('From: <a@b.example>, <c@d.example>')).findings.map((f) => f.id)).toContain('multiple-from');
    expect((await run('From: Alice <a@b.example>')).findings.map((f) => f.id)).not.toContain('multiple-from');
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

  it('handles garbage input without throwing', async () => {
    const junk = await analyze('\x00\xff random bytes \n\n\n--x--');
    expect(junk.level).toBe('low');
  });
  it('refuses a file that holds only a byte order mark, blanks or zero bytes instead of calling it low risk', async () => {
    // An empty document saved by Notepad (UTF-8 or "Unicode") or a download that failed as zeros scored 0, "Low risk".
    for (const empty of ['', '\xEF\xBB\xBF', '\xEF\xBB\xBF\r\n \n', '\xFF\xFE', '\xFF\xFE \0\n\0', '\xFE\xFF', '\0\0\0\0']) {
      await expect(analyze(empty), JSON.stringify(empty)).rejects.toThrow('contains no text');
    }
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
    expect(a.findings.find((f) => f.id === 'data-uri')?.evidence).toHaveLength(20000); // the rest are past the link limit
    expect(performance.now() - t).toBeLessThan(1500); // was about 8 s with evidence.includes()
  });
  it('checks the first 20,000 distinct links and says how many were left out', async () => {
    const pad = Array.from({ length: 20_100 }, (_, i) => `<a href="https://h${i}.example/">${i}</a>`).join('');
    const t = performance.now();
    const a = await analyze(`From: a@b.example\nContent-Type: text/html\n\n<a href="https://paypa1.example/">x</a>${pad}`);
    expect(performance.now() - t).toBeLessThan(3000);
    expect(a.links).toHaveLength(20_000);
    expect(a.links[0].host).toBe('paypa1.example'); // the email's own links come first
    expect(a.findings.find((f) => f.id === 'too-many-links')).toMatchObject({ severity: 'medium', evidence: ['101 more distinct links after the first 20,000 were not checked'] });
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
