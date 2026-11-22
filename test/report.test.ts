import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { analyze } from '../src/core/analyze';
import { bytesToBinary, textToBinary } from '../src/core/encoding';
import { code, defang, toMarkdown } from '../src/core/report';

const sample = (name: string) => analyze(bytesToBinary(new Uint8Array(readFileSync(new URL(`../samples/${name}`, import.meta.url)))));

/** What a CommonMark renderer shows for a code span (spec 6.1): fences off, one edge space stripped when both edges have one. */
function renderSpan(span: string): string {
  const fence = /^`+/.exec(span)![0];
  expect(span.endsWith(fence)).toBe(true);
  let inner = span.slice(fence.length, -fence.length);
  // No backtick run of exactly the fence's length inside, or the span would end early.
  expect(inner.match(/`+/g)?.some((r) => r.length === fence.length) ?? false).toBe(false);
  if (inner.length > 2 && inner.startsWith(' ') && inner.endsWith(' ') && inner.trim()) inner = inner.slice(1, -1);
  return inner;
}

/** The report with every code span and fenced block removed: what is left is rendered as Markdown. */
const outsideCode = (md: string) => md.replace(/^(`{3,})text\n[\s\S]*?\n\1$/gm, '').replace(/(`+)(?:(?!\1)[\s\S])*?[^`]\1(?!`)/g, '');

describe('code spans for email text', () => {
  it.each([
    'plain',
    'a `tick` here',
    '``double`` and `single`',
    '`starts with a tick',
    'ends with a tick`',
    ' leading space',
    ' both sides ',
    '[click](https://evil.example) ![x](https://evil.example/t.png) <img src=x>',
  ])('renders %j exactly', (s) => {
    expect(renderSpan(code(s))).toBe(s);
  });

  it('keeps everything on one line and shows hidden characters', () => {
    expect(code('a\r\nb\u2028c')).toBe('`a b c`');
    expect(code('pay\u202Elapyap')).toBe('`pay⟨U+202E⟩lapyap`');
    expect(code('bell\u0007 c1\u0085')).toBe('`bell\\u0007 c1\\u0085`');
    expect(code('  ')).toBe('(empty)');
  });
});

describe('defang', () => {
  it('breaks the scheme and every dot of the host, not the path', () => {
    expect(defang('https://a.b.example/x.zip?q=1.2')).toBe('hxxps://a[.]b[.]example/x.zip?q=1.2');
    expect(defang('data:text/html,hi')).toBe('data:text/html,hi');
  });
});

describe('Markdown report', () => {
  it('reports the forwarded sample with the attached email nested one level down', async () => {
    const md = toMarkdown(await sample('06-user-report-forwarded.eml'));
    expect(md.startsWith('# Email report: `Fwd: Your account has been limited - is this real?`\n\n**Score 37/100: Suspicious.**')).toBe(true);
    expect(md).toContain('## Attached email `Your account has been limited.eml`\n\n**Score 100/100: High risk.**');
    expect(md).toContain('### Reasons');
    expect(md).toContain('- `hxxps://xn--pypal-4ve[.]example/signin?session=8812` (text `https://www.paypal.com/signin`; unwrapped from Microsoft Safe Links)');
    expect(md).toContain('```text\npaypa1-secure[.]example\n');
    expect(md).toMatch(/^sha256:[0-9a-f]{64}$/m);
    // Nothing outside code renders as a link: every URL and domain is defanged or inside a code span.
    expect(outsideCode(md)).not.toMatch(/https?:\/\/|www\./);
  });

  it('lists attachment hashes and the score breakdown for the macro invoice', async () => {
    const a = await sample('02-invoice-macro.eml');
    const md = toMarkdown(a);
    for (const att of a.attachments) expect(md).toContain(`SHA-256 \`${att.sha256}\``);
    expect(md).toContain('- **High, +25:** ');
    expect(md).toContain('## What to do next\n\n1. Treat this email as phishing');
  });

  it('never lets email content become Markdown links, images, HTML or headings', async () => {
    const hostile = [
      'From: "[Support](https://evil.example/a) ![t](https://evil.example/t.png)" <x@evil.example>',
      'Subject: `` ` <img src=x onerror=alert(1)> **bold**',
      'Authentication-Results: mx.b.example; dmarc=fail header.from=evil_*x*<b>.example',
      'Received: from evil.example by mx.b.example; Tue, 10 Nov 2026 09:00:00 +0000',
      'Content-Type: text/html',
      '',
      '<a href="https://evil.example/`x`">```\n# Heading\n[y](https://evil.example)</a>',
    ].join('\n');
    const md = toMarkdown(await analyze(textToBinary(hostile)));
    const rendered = outsideCode(md);
    expect(rendered).not.toMatch(/\]\(|<img|https?:\/\//);
    expect(md.split('\n').filter((l) => l.startsWith('#')).every((l) => /^#+ (Email report|Message|Reasons|Points|Authentication|Delivery|Links|Attachments|Observables|What to do)/.test(l))).toBe(true);
    // The domain quoted in the DMARC explanation is escaped, not turned into emphasis or HTML.
    expect(md).toContain('The visible From domain (evil\\_\\*x\\*\\<b\\>.example) failed DMARC');
  });

  it('defangs domains our sentences quote from the email, so nothing autolinks them', async () => {
    const md = toMarkdown(await analyze(textToBinary([
      'Authentication-Results: mx.b.example; dmarc=fail header.from=www.evil.example; spf=pass smtp.mailfrom=ops@evil.example',
      'Received: from evil.example by mx.b.example; Tue, 10 Nov 2026 09:00:00 +0000',
      'From: a@www.evil.example',
      '',
      'hi',
    ].join('\n'))));
    expect(md).toContain('The visible From domain (www[.]evil[.]example) failed DMARC');
    expect(outsideCode(md)).not.toMatch(/www\.|@\w+\.\w/);
  });

  it('caps long lists and says where the rest is', async () => {
    const links = Array.from({ length: 250 }, (_, i) => `https://h${i}.example/`).join('\n');
    const md = toMarkdown(await analyze(textToBinary(`From: a@b.example\nSubject: many\n\n${links}\n`)));
    expect(md).toContain('- 50 more not listed; the JSON report has all of them.');
    expect(md).toContain('more not listed; the JSON report has all of them.\n\n## What to do next');
  });
});
