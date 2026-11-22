// Timing fuzz: hostile 60 KB inputs built from repeated syntax fragments, the shape that makes a
// regex or loop go quadratic. Opt-in because it takes about a minute: `npm run fuzz` (FUZZ_CASES=n, FUZZ_SEED=n).
import { describe, expect, it } from 'vitest';
import { analyze } from '../src/core/analyze';
import { toMarkdown } from '../src/core/report';

const VOCAB = ['(', ')', '<', '>', '"', "'", '=', ';', ':', ',', '.', '@', '/', '\\', ' ', '\t', '\n', '\r', '\r\n', '-', '_', '*', '?', '&', '#', '%', 'a', 'x', '1', '[', ']', 'X', '!',
  '<a ', 'href=', '</a>', '<!--', '-->', '<script', '<base ', '=?', '?=', 'B?', 'Q?', 'http://', 'https://', '//', 'www.', 'xn--', 'from ', ' by ', ' with ', 'spf=', 'dkim=', 'pass', '.pdf', '.exe',
  '&#', '&amp;', '&shy;', '\n--b', '--', 'boundary=b', 'Content-Type: ', 'multipart/mixed; ', 'text/html', 'base64', 'filename*0*=', "utf-8''", '%41', 'paypal', 'urgent ', 'verify your ',
  'account ', 'i=1', 'cv=pass', 'smtp.mailfrom=', 'header.d=', '127.1', 'data:', 'bit.ly/',
  '/URI', '/JS', '#4', 'stream\n', 'endstream', ' obj', '<<', '>>', '/Type/ObjStm', '/FlateDecode', '\\0'];
const HEADERS = ['From', 'Reply-To', 'Return-Path', 'Sender', 'To', 'Subject', 'Date', 'Received', 'Authentication-Results', 'ARC-Authentication-Results', 'ARC-Seal', 'Content-Type', 'Content-Disposition', 'Content-Transfer-Encoding', 'Received-SPF'];
const SIZE = 60000;
const LIMIT_MS = 500; // linear code takes under 40 ms; every quadratic bug found so far took 1-20 s

const place = (where: number, header: string, blob: string) =>
  [
    `${header}: ${blob}\nFrom: a@b.example\nReceived: from x by mx.b.example; Tue, 10 Nov 2026 09:00:00 +0000\n\nhi`,
    `From: a@b.example\nContent-Type: text/html\n\n${blob}`,
    `From: a@b.example\nContent-Type: multipart/mixed; boundary=b\n\n--b\n${header}: ${blob.replace(/\n/g, ' ')}\n\n${blob}\n--b--\n`,
    // Attachments whose content is scanned for links: a PDF and an HTML page.
    `From: a@b.example\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Disposition: attachment; filename=a.pdf\n\n%PDF-1.7\n${blob}\n--b--\n`,
    `From: a@b.example\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Disposition: attachment; filename=a.html\n\n${blob}\n--b--\n`,
  ][where];

describe.runIf(process.env.FUZZ)('timing fuzz', () => {
  it('analyzes every generated input quickly and without throwing', async () => {
    let seed = Number(process.env.FUZZ_SEED ?? 1);
    const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
    const pick = <T,>(a: T[]) => a[Math.floor(rnd() * a.length)];
    const slow: string[] = [];
    const check = async (header: string, where: number, motif: string, prefix: string) => {
      const blob = prefix + motif.repeat(Math.ceil(SIZE / motif.length)).slice(0, SIZE) + pick(VOCAB) + pick(VOCAB);
      const t = performance.now();
      toMarkdown(await analyze(place(where, header, blob)));
      const ms = performance.now() - t;
      if (ms > LIMIT_MS) slow.push(`${ms.toFixed(0)} ms: ${header} (${where}) ${JSON.stringify(blob.slice(0, 60))}`);
    };
    // Every single fragment repeated in every header and body position: the shape of every bug found so far.
    for (const header of HEADERS) for (let where = 0; where < 5; where++) for (const motif of VOCAB) await check(header, where, motif, pick(VOCAB));
    // Then random mixes of up to four fragments.
    for (let i = 0; i < Number(process.env.FUZZ_CASES ?? 10000); i++) {
      const motif = Array.from({ length: 1 + Math.floor(rnd() * 4) }, () => pick(VOCAB)).join('');
      await check(pick(HEADERS), Math.floor(rnd() * 5), motif, rnd() < 0.5 ? pick(VOCAB) + pick(VOCAB) : '');
    }
    expect(slow).toEqual([]);
  }, 900_000);
});
