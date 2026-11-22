import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { analyze } from '../src/core/analyze';
import { bytesToBinary } from '../src/core/encoding';

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

  it('handles empty and garbage input without throwing', async () => {
    expect((await analyze('')).score).toBe(0);
    const junk = await analyze('\x00\xff random bytes \n\n\n--x--');
    expect(junk.level).toBe('low');
  });
});
