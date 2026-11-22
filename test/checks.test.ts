import { describe, expect, it } from 'vitest';
import { inspectAttachment, sniffKind } from '../src/core/attachments';
import { inspectDomain, orgDomain, skeleton } from '../src/core/domains';
import { scanLanguage } from '../src/core/language';
import { decodePunycodeLabel, toUnicodeDomain } from '../src/core/punycode';
import { analyzeLink, extractHtmlLinks, extractTextLinks } from '../src/core/urls';
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
});

describe('domains', () => {
  it('finds the registrable domain, including two-label suffixes', () => {
    expect(orgDomain('a.b.paypal.co.uk')).toBe('paypal.co.uk');
    expect(orgDomain('mail.example.com.')).toBe('example.com');
  });
  it('maps confusables to a common skeleton', () => {
    expect(skeleton('rnicr0soft')).toBe(skeleton('microsoft'));
  });
  it('leaves real brand domains and unrelated domains alone', () => {
    expect(inspectDomain('mail.paypal.com')).toEqual([]);
    expect(inspectDomain('accounts.google.com')).toEqual([]);
    expect(inspectDomain('northwind-garden.example')).toEqual([]);
    expect(inspectDomain('live-scores.example')).toEqual([]); // generic brand label "live" is ignored
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
  it('flags double extensions, executables, HTML, RLO names and type mismatches', () => {
    expect(attIssues('invoice.pdf.exe', 'MZ')).toEqual(['double-extension', 'executable']);
    expect(attIssues('statement.pdf   .html', '<html></html>')).toEqual(['double-extension', 'html-attachment']);
    expect(attIssues('photo‮gpj.exe', 'MZ')).toEqual(['rlo-filename', 'executable']);
    expect(attIssues('invoice.pdf', 'MZ\x90\x00')).toEqual(['type-mismatch']);
    expect(attIssues('invoice.pdf', '%PDF-1.7')).toEqual([]);
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
  it('finds nothing in ordinary text', () => {
    expect(scanLanguage('Here are the meeting notes from Tuesday. See you next week.')).toEqual([]);
  });
});
