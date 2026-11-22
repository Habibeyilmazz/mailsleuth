import { describe, expect, it } from 'vitest';
import { inspectAttachment, sniffKind } from '../src/core/attachments';
import { inspectDomain, orgDomain, skeleton } from '../src/core/domains';
import { scanLanguage } from '../src/core/language';
import { decodePunycodeLabel, toUnicodeDomain } from '../src/core/punycode';
import { htmlToText } from '../src/core/encoding';
import { analyzeLink, extractHtmlLinks, extractTextLinks, isIgnorableHref } from '../src/core/urls';
import { makeZip } from '../scripts/zip.ts';

const kinds = (d: string) => inspectDomain(d).map((i) => i.kind);
const linkIssues = (href: string, text: string | null = null) => analyzeLink(href, text, 'html').issues.map((i) => i.id);
const attIssues = (name: string, data: Uint8Array | string) =>
  inspectAttachment(name, typeof data === 'string' ? new TextEncoder().encode(data) : data).issues.map((i) => i.id);

describe('punycode', () => {
  it('decodes RFC 3492 labels', () => {
    expect(decodePunycodeLabel('pypal-4ve')).toBe('pаypal'); // Cyrillic а
    expect(decodePunycodeLabel('mnchen-3ya')).toBe('münchen');
    expect(toUnicodeDomain('xn--80ak6aa92e.example')).toBe('аррӏе.example');
  });
  it('returns the label unchanged when it is not valid punycode', () => {
    expect(toUnicodeDomain('xn--!!.example')).toBe('xn--!!.example');
  });
  it('leaves labels longer than DNS allows undecoded instead of crashing', () => {
    const huge = 'xn--' + 'a'.repeat(200000) + '-ba';
    expect(toUnicodeDomain(`${huge}.example`)).toBe(`${huge}.example`);
    expect(decodePunycodeLabel('a'.repeat(54) + '-ba')).not.toBeNull(); // 63 octets with "xn--": still decoded
  });
});

describe('domains', () => {
  it('finds the registrable domain, including two-label suffixes', () => {
    expect(orgDomain('a.b.paypal.co.uk')).toBe('paypal.co.uk');
    expect(orgDomain('mail.example.com.')).toBe('example.com');
    expect(orgDomain('victim.github.io')).not.toBe(orgDomain('evil.github.io'));
  });
  it('maps confusables to a common skeleton', () => {
    expect(skeleton('rnicr0soft')).toBe(skeleton('microsoft'));
  });
  it('leaves real brand domains and unrelated domains alone', () => {
    expect(inspectDomain('mail.paypal.com')).toEqual([]);
    expect(inspectDomain('accounts.google.com')).toEqual([]);
    expect(inspectDomain('northwind-garden.example')).toEqual([]);
    expect(inspectDomain('live-scores.example')).toEqual([]); // generic brand label "live" is ignored
    // Everyday words one edit away from a brand are not look-alikes.
    for (const d of ['cloud.example', 'pcloud.com', 'acme-finance.com', 'strip.example', 'witter.example', 'status.cloud.vendor.example']) {
      expect(inspectDomain(d)).toEqual([]);
    }
  });
  it('flags homoglyph, typo and brand-in-domain lookalikes', () => {
    expect(kinds('xn--pypal-4ve.com')).toEqual(['idn', 'homoglyph']);
    expect(kinds('paypa1-secure.example')).toEqual(['lookalike']);
    expect(kinds('amazom.example')).toEqual(['lookalike']);
    expect(kinds('paypal.com.session-review.example')).toEqual(['brand-in-domain']);
    expect(kinds('dhl-parcel.top')).toEqual(['brand-in-domain', 'abused-tld']);
  });
});

describe('links', () => {
  it('resolves relative links against <base href> like mail clients do', () => {
    const html = '<base href="https://evil.example/kit/"><a href="login.html">Sign in</a><a href="https://ok.example/">x</a><a href="#top">top</a>';
    expect(extractHtmlLinks(html).map((l) => l.href)).toEqual(['https://evil.example/kit/login.html', 'https://ok.example/', '#top']);
    expect(extractHtmlLinks('<a href="login.html">x</a>')[0].href).toBe('login.html');
  });
  it('trims trailing punctuation from text links in linear time', () => {
    expect(extractTextLinks('see www.example.com/a.')).toEqual(['http://www.example.com/a']);
    const t = performance.now();
    extractTextLinks('www.' + ','.repeat(200000) + 'X');
    expect(performance.now() - t).toBeLessThan(500);
  });
  it('finds protocol-relative and SVG xlink:href links', () => {
    expect(extractHtmlLinks('<a href="//evil.example/a.exe">x</a>')[0].href).toBe('https://evil.example/a.exe');
    expect(extractHtmlLinks('<svg><a xlink:href="https://evil.example/a.exe"><text>x</text></a></svg>')[0].href).toBe('https://evil.example/a.exe');
  });
  it('reads hosts the way the browser does when &shy; hides inside them', () => {
    const [l] = extractHtmlLinks('<a href="https://pay&shy;pa1.example/login">Sign in</a>');
    expect(analyzeLink(l.href, l.text, 'html').host).toBe('paypa1.example');
  });
  it('unwraps Safe Links, Google, Proofpoint v2/v3 and Facebook wrappers', () => {
    const safe = analyzeLink('https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Fx&data=1', null, 'html');
    expect([safe.finalUrl, safe.unwrappedVia]).toEqual(['https://evil.example/x', ['Microsoft Safe Links']]);
    expect(analyzeLink('https://www.google.com/url?q=https://evil.example/', null, 'html').host).toBe('evil.example');
    expect(analyzeLink('https://urldefense.proofpoint.com/v2/url?u=https-3A__evil-2Dsite.example_a&d=x', null, 'html').finalUrl).toBe('https://evil-site.example/a');
    expect(analyzeLink('https://urldefense.com/v3/__https://evil.example/p__;!!abc$', null, 'html').host).toBe('evil.example');
    expect(analyzeLink('https://l.facebook.com/l.php?u=https%3A%2F%2Fevil.example%2F', null, 'html').host).toBe('evil.example');
  });
  it('flags text/href mismatch but not matching text or wrapped matching destinations', () => {
    expect(linkIssues('https://evil.example/login', 'https://www.paypal.com/')).toContain('text-mismatch');
    expect(linkIssues('https://www.paypal.com/signin', 'paypal.com')).toEqual([]);
    expect(linkIssues('https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.paypal.com%2F', 'www.paypal.com')).toEqual([]);
    expect(linkIssues('https://evil.example/', 'Click here')).toEqual([]);
  });
  it('reads a file name or "Node.js" in link text as a name, not as a site', () => {
    // A shared-file notification links the file name to the file host; that is not a lie about the destination.
    for (const text of ['Q3-Report.pdf', 'Budget.xlsx', 'Node.js', 'photo.JPG', 'notes.txt']) {
      expect(linkIssues('https://contoso.sharepoint.example/s/abc', text)).toEqual([]);
    }
    // Endings that are real top-level domains still name a site.
    expect(linkIssues('https://evil.example/', 'paypal.com')).toContain('text-mismatch');
    expect(linkIssues('https://evil.example/', 'update.zip')).toContain('text-mismatch');
    expect(linkIssues('https://evil.example/', 'https://paypal.pdf/')).toContain('text-mismatch'); // with a scheme it is a URL
  });
  it("notes a newsletter's click tracking instead of calling its own site a mismatch", () => {
    const tracked = (text: string, from: string) => analyzeLink('https://shop.us5.list-manage.com/track/click?u=1', text, 'html', from).issues.map((i) => i.id);
    expect(tracked('www.shop.example', 'shop.example')).toEqual(['tracked-link']);
    expect(tracked('www.shop.example', 'news.shop.example')).toEqual(['tracked-link']);
    // Text naming someone else's site, or no known sender, stays a mismatch.
    expect(tracked('www.paypal.com', 'shop.example')).toEqual(['text-mismatch']);
    expect(tracked('www.shop.example', '')).toEqual(['text-mismatch']);
    // Only known mailing-service trackers: any other host is still a mismatch.
    expect(analyzeLink('https://evil.example/c', 'www.shop.example', 'html', 'shop.example').issues.map((i) => i.id)).toEqual(['text-mismatch']);
  });
  it('flags IP literals, including disguised decimal form', () => {
    const l = analyzeLink('http://3325256727/x', null, 'html');
    expect(l.host).toBe('198.51.100.23');
    expect(l.issues[0].detail).toContain('disguised');
    expect(linkIssues('http://[2001:db8::1]/')).toEqual(['ip-host']);
  });
  it('flags userinfo, shorteners, data/javascript URIs, redirects and risky downloads', () => {
    expect(linkIssues('https://paypal.com@evil.example/')).toEqual(['userinfo']);
    expect(linkIssues('https://bit.ly/abc')).toEqual(['shortener']);
    expect(linkIssues('data:text/html;base64,AAAA')).toEqual(['data-uri']);
    expect(linkIssues('javascript:alert(1)')).toEqual(['javascript-uri']);
    expect(linkIssues('https://trusted.example/out?next=https://evil.example/')).toEqual(['open-redirect']);
    expect(linkIssues('https://files.example/invoice.iso')).toEqual(['risky-download']);
  });
  it('flags links that open a file share or start a program (NTLM leak, search-ms, Follina)', () => {
    expect(linkIssues('file:///\\\\192.0.2.7\\share\\doc.rtf!x')).toEqual(['local-link']); // CVE-2024-21413 "MonikerLink"
    expect(linkIssues('file://evil.example/share/x.exe')).toEqual(['local-link']);
    expect(linkIssues('\\\\evil.example\\share\\x.exe')).toEqual(['local-link']);
    expect(linkIssues('search-ms:query=invoice&crumb=location:\\\\evil.example\\s')).toEqual(['local-link']);
    expect(linkIssues('ms-msdt:/id PCWDiagnostic')).toEqual(['local-link']);
    expect(linkIssues('https://www.google.com/url?q=file://evil.example/s/x.lnk')).toEqual(['local-link']);
    expect(linkIssues('vbscript:msgbox(1)')).toEqual(['javascript-uri']);
    expect(isIgnorableHref('\\\\evil.example\\share')).toBe(false);
    expect(isIgnorableHref('images/logo.png')).toBe(true);
  });
  it('strips leading control characters from hrefs like browsers do', () => {
    expect(extractHtmlLinks('<a href=" \u0001javascript:alert(1)">x</a>')[0].href).toBe('javascript:alert(1)');
  });
  it('does not trust look-alike wrapper hosts and survives bad percent-encoding', () => {
    const fake = analyzeLink('https://google.attacker.example/url?q=https%3A%2F%2Fpaypal.com', 'paypal.com', 'html');
    expect(fake.unwrappedVia).toEqual([]);
    expect(fake.issues.map((i) => i.id)).toContain('text-mismatch');
    expect(linkIssues('https://%FF@evil.example/')).toEqual(['userinfo']);
    expect(linkIssues('https://www.google.com/url?q=javascript:alert(1)')).toEqual(['javascript-uri']);
  });
  it('reads the real href, not data-href, and strips URL whitespace like browsers do', () => {
    expect(extractHtmlLinks('<a data-href="https://paypal.com" href="https://evil.example/">x</a>')[0].href).toBe('https://evil.example/');
    expect(extractHtmlLinks('<a href="java&#10;script:alert(1)">go</a>')[0].href).toBe('javascript:alert(1)');
    expect(extractHtmlLinks(`<a title=" href='https://paypal.com/'" href="https://evil.example/">x</a>`)[0].href).toBe('https://evil.example/');
    expect(extractHtmlLinks('<a name=top>x</a>')).toEqual([]);
    expect(extractHtmlLinks('<a href="https://a.example/">one<a href="https://b.example/">two')).toEqual([
      { href: 'https://a.example/', text: 'one' },
      { href: 'https://b.example/', text: 'two' },
    ]);
  });
  it('stays fast on thousands of unterminated tags', () => {
    const t = performance.now();
    for (const junk of ['<a title="', '<a ', '<script', '<!--', '<']) {
      extractHtmlLinks(junk.repeat(50000));
      htmlToText(junk.repeat(50000));
    }
    expect(performance.now() - t).toBeLessThan(1000);
  });
  it('reads link text and hrefs the way a browser renders them', () => {
    expect(extractHtmlLinks('<a href="https://evil.example/"><span>pay</span><span>pal.com</span></a>')[0].text).toBe('paypal.com');
    expect(extractHtmlLinks('<a href="https://e.example/">Visit<br>paypal.com</a>')[0].text).toBe('Visit paypal.com');
    expect(extractHtmlLinks('<a href="https&colon;//evil.example/login">x</a>')[0].href).toBe('https://evil.example/login');
    expect(extractHtmlLinks('<a title="balance > 0" href="https://evil.example/">x</a><form class="a>b" action="https://f.example/">')).toEqual([
      { href: 'https://evil.example/', text: 'x' },
      { href: 'https://f.example/', text: '(form submit)' },
    ]);
  });
  it('extracts links from HTML (with entities) and plain text', () => {
    expect(extractHtmlLinks(`<a class=x href='https://a.example/?a=1&amp;b=2'><b>Go</b> now</a><form action=https://b.example/post>`)).toEqual([
      { href: 'https://a.example/?a=1&b=2', text: 'Go now' },
      { href: 'https://b.example/post', text: '(form submit)' },
    ]);
    expect(extractTextLinks('see www.a.example/x. and (https://b.example/y)')).toEqual(['http://www.a.example/x', 'https://b.example/y']);
  });
});

describe('attachments', () => {
  const ooxml = (extra: { name: string; data: string }[]) => makeZip([{ name: '[Content_Types].xml', data: '<Types/>' }, ...extra]);

  it('detects VBA macros in OOXML by structure, whatever the extension', () => {
    expect(attIssues('report.docx', ooxml([{ name: 'word/vbaProject.bin', data: 'x' }]))).toEqual(['office-macro']);
    expect(attIssues('report.docx', ooxml([{ name: 'word/document.xml', data: 'x' }]))).toEqual([]);
    expect(attIssues('report.xlsm', ooxml([]))).toEqual(['macro-enabled-type']);
  });
  it('detects VBA storage in legacy OLE files', () => {
    const ole = new Uint8Array([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, ...new TextEncoder().encode('_VBA_PROJECT'.split('').join('\0') + '\0')]);
    expect(sniffKind(ole)).toBe('ole');
    expect(attIssues('old.doc', ole)).toEqual(['office-macro']);
  });
  it('inspects ZIP contents and encryption', () => {
    expect(attIssues('docs.zip', makeZip([{ name: 'scan.pdf.lnk', data: 'x' }]))).toEqual(['archive-risky-content']);
    expect(attIssues('docs.zip', makeZip([{ name: 'a.txt', data: 'x', encrypted: true }]))).toEqual(['encrypted-archive']);
  });
  it('calls a password-protected .docx/.xlsx encrypted, not a type mismatch', () => {
    // Office stores an encrypted OOXML file in an OLE container with an "EncryptedPackage" stream.
    const ole = (stream: string) => new Uint8Array([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, ...new TextEncoder().encode(stream.split('').join('\0') + '\0')]);
    expect(attIssues('q3.xlsx', ole('EncryptedPackage'))).toEqual(['encrypted-archive']);
    expect(attIssues('q3.docm', ole('EncryptedPackage'))).toEqual(['encrypted-archive', 'macro-enabled-type']);
    expect(attIssues('q3.xlsx', ole('Workbook'))).toEqual(['type-mismatch']); // a renamed .xls is still a mismatch
  });
  it('flags double extensions, executables, HTML, RLO names and type mismatches', () => {
    expect(attIssues('invoice.pdf.exe', 'MZ')).toEqual(['double-extension', 'executable']);
    expect(attIssues('statement.pdf   .html', '<html></html>')).toEqual(['double-extension', 'html-attachment']);
    expect(attIssues('invoice.pdf\u200b.exe', 'MZ')).toEqual(['double-extension', 'executable']); // zero-width space: still looks like .pdf.exe
    expect(attIssues('photo\u202Egpj.exe', 'MZ')).toEqual(['rlo-filename', 'executable']);
    // The "real name" must be readable: JSON.stringify left the U+202E in place, so it still displayed reversed.
    expect(inspectAttachment('photo\u202Egpj.exe', new Uint8Array()).issues[0].detail).toContain('"photo⟨U+202E⟩gpj.exe"');
    expect(attIssues('photo\u202Bgpj.exe', 'MZ')).toEqual(['rlo-filename', 'executable']);
    expect(attIssues('invoice.pdf', 'MZ\x90\x00')).toEqual(['type-mismatch']);
    expect(attIssues('invoice.pdf', '%PDF-1.7')).toEqual([]);
  });
  it('flags programs recognized by content even without an extension', () => {
    expect(attIssues('unnamed-attachment', 'MZ\x90\x00')).toEqual(['executable']);
  });
  it('survives attacker-chosen extensions that are Object.prototype names', () => {
    expect(inspectAttachment('x.constructor', new Uint8Array([0x4d, 0x5a, 0, 0])).issues.map((i) => i.id)).toEqual(['executable']);
  });
  it('recognizes ISO and LNK by magic bytes', () => {
    const iso = new Uint8Array(0x8010);
    iso.set(new TextEncoder().encode('CD001'), 0x8001);
    expect(attIssues('photos.img', iso)).toEqual(['disk-image']);
    expect(sniffKind(new Uint8Array([0x4c, 0, 0, 0, 1, 0x14, 2, 0]))).toBe('lnk');
  });
});

describe('language', () => {
  it('reports each category with the matched phrase', () => {
    const hits = scanLanguage('URGENT: verify your account within 24 hours. Buy gift cards. Legal action follows.');
    expect(hits.map((h) => h.category)).toEqual(['urgency', 'urgency', 'credentials', 'money', 'threat']);
    expect(hits.map((h) => h.phrase)).toContain('verify your account');
  });
  it('reads phrases split by invisible characters or written with look-alike letters', () => {
    // A known filter evasion; the reader sees "verify your account" in each case.
    for (const text of ['Please ver\u00adify your acc\u200bount', 'Please \uff56\uff45\uff52\uff49\uff46\uff59 y\u043eur acc\u043eunt', 'V\u0415RIFY Y\u041eUR ACCOUNT']) {
      expect(scanLanguage(text).map((h) => h.category), text).toContain('credentials');
    }
  });
  it('finds nothing in ordinary text', () => {
    expect(scanLanguage('Here are the meeting notes from Tuesday. See you next week.')).toEqual([]);
    // "court" on its own is a tennis or food court, not a threat.
    expect(scanLanguage('The new tennis court opens Saturday; lunch is at the food court.')).toEqual([]);
  });
  it('still reads court threats', () => {
    for (const text of ['You will be taken to court.', 'A court order has been issued.', 'Ignoring this court summons', 'We will see you in court']) {
      expect(scanLanguage(text).map((h) => h.category), text).toEqual(['threat']);
    }
  });
});
