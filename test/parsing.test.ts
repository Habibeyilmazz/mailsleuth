import { describe, expect, it } from 'vitest';
import { parseAddressList, parseReturnPath } from '../src/core/address';
import { buildAuthReport, parseAuthResults } from '../src/core/auth';
import { decodeHeaderValue, decodeQuotedPrintable, htmlToText, sha256Hex, textToBinary } from '../src/core/encoding';
import { isAttachment, parseMessage, parseStructuredHeader, walkParts } from '../src/core/mime';
import { buildHops, parseReceived } from '../src/core/received';

const dec = (b: Uint8Array) => new TextDecoder().decode(b);

describe('encoding', () => {
  it('decodes RFC 2047 B and Q words and joins adjacent ones', () => {
    expect(decodeHeaderValue('=?UTF-8?B?w5xyw7xu?= =?UTF-8?Q?_fiyat=C4=B1?=')).toBe('Ürün fiyatı');
    expect(decodeHeaderValue('=?iso-8859-1?q?caf=E9?= ok')).toBe('café ok');
  });
  it('keeps raw UTF-8 headers (RFC 6532)', () => {
    expect(decodeHeaderValue(textToBinary('Grüße'))).toBe('Grüße');
  });
  it('decodes quoted-printable soft line breaks', () => {
    expect(dec(decodeQuotedPrintable('ab=\ncd=3D=C3=A9'))).toBe('abcd=é');
  });
  it('turns HTML into visible text without script/style', () => {
    expect(htmlToText('<style>x{}</style><p>Hi&nbsp;there</p><script>evil()</script><p>&amp; bye</p>')).toBe('Hi there\n& bye');
  });
  it('hashes with SHA-256', async () => {
    expect(await sha256Hex(new TextEncoder().encode('abc'))).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
});

describe('mime', () => {
  it('parses RFC 2231 encoded and continued parameters', () => {
    const p = parseStructuredHeader(`attachment; filename*0*=utf-8''Fatura%20; filename*1="2026.pdf"`);
    expect(p.value).toBe('attachment');
    expect(p.params['filename']).toBe('Fatura 2026.pdf');
  });
  it('walks nested multiparts and decodes base64 attachments', () => {
    const raw = [
      'From: a@example.com',
      'Content-Type: multipart/mixed; boundary="outer"',
      '',
      'preamble',
      '--outer',
      'Content-Type: multipart/alternative; boundary=inner',
      '',
      '--inner',
      'Content-Type: text/plain',
      '',
      'plain body',
      '--inner',
      'Content-Type: text/html',
      '',
      '<p>html body</p>',
      '--inner--',
      '--outer',
      'Content-Type: application/octet-stream',
      'Content-Disposition: attachment; filename="a.bin"',
      'Content-Transfer-Encoding: base64',
      '',
      'aGVsbG8=',
      '--outer--',
      'epilogue',
    ].join('\r\n');
    const parts = [...walkParts(parseMessage(raw))];
    expect(parts.map((p) => p.contentType)).toEqual(['multipart/mixed', 'multipart/alternative', 'text/plain', 'text/html', 'application/octet-stream']);
    expect(dec(parts[2].body)).toBe('plain body');
    const att = parts.find(isAttachment)!;
    expect(att.filename).toBe('a.bin');
    expect(dec(att.body)).toBe('hello');
  });
  it('tolerates a missing closing boundary', () => {
    const msg = parseMessage('Content-Type: multipart/mixed; boundary=b\n\n--b\n\nonly part\n');
    expect(msg.children).toHaveLength(1);
    expect(dec(msg.children[0].body).trim()).toBe('only part');
  });
  it('treats header-only input (pasted headers) as a message with an empty body', () => {
    const msg = parseMessage('Subject: hi\nFrom: a@example.com');
    expect(msg.headers).toHaveLength(2);
    expect(msg.body.length).toBe(0);
  });
});

describe('addresses', () => {
  it('parses names, quoted commas, encoded names and bare addresses', () => {
    const list = parseAddressList('"Doe, Jane" <jane@example.com>, =?UTF-8?Q?Jos=C3=A9?= <jose@Example.ORG>, bob@example.net (Bob)');
    expect(list).toEqual([
      { name: 'Doe, Jane', address: 'jane@example.com', domain: 'example.com' },
      { name: 'José', address: 'jose@Example.ORG', domain: 'example.org' },
      { name: 'Bob', address: 'bob@example.net', domain: 'example.net' },
    ]);
  });
  it('ignores empty bounce Return-Path', () => {
    expect(parseReturnPath('<>')).toBeNull();
    expect(parseReturnPath('<b@x.example>')?.domain).toBe('x.example');
  });
});

describe('received', () => {
  it('extracts from/by/ip/protocol/date', () => {
    const h = parseReceived('from mail.a.example (mail.a.example [203.0.113.5]) by mx.b.example with ESMTPS id 1; Tue, 10 Nov 2026 09:00:00 +0100 (CET)');
    expect(h).toMatchObject({ from: 'mail.a.example', fromIp: '203.0.113.5', by: 'mx.b.example', protocol: 'ESMTPS', date: '2026-11-10T08:00:00.000Z' });
  });
  it('orders hops oldest first and computes delays', () => {
    const hops = buildHops([
      'from b by c; Tue, 10 Nov 2026 09:05:00 +0000',
      'from a by b; Tue, 10 Nov 2026 09:00:00 +0000',
    ]);
    expect(hops.map((h) => [h.index, h.from, h.delaySeconds])).toEqual([[1, 'a', null], [2, 'b', 300]]);
  });
});

describe('authentication results', () => {
  it('parses a Google-style header with comments and properties', () => {
    const ar = parseAuthResults(
      'mx.google.example; dkim=pass header.i=@shop.example header.s=s1; spf=softfail (domain of x@bounce.shop.example does not designate 1.2.3.4) smtp.mailfrom=x@bounce.shop.example; dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=shop.example',
    );
    expect(ar.authservId).toBe('mx.google.example');
    expect(ar.results.map((r) => [r.method, r.result, r.domain])).toEqual([
      ['dkim', 'pass', 'shop.example'],
      ['spf', 'softfail', 'bounce.shop.example'],
      ['dmarc', 'fail', 'shop.example'],
    ]);
    expect(ar.results[2].explanation).toContain('p=reject');
    expect(ar.results[2].tone).toBe('bad');
  });
  it('parses Microsoft-style headers without an authserv-id', () => {
    const ar = parseAuthResults('spf=fail (sender IP is 203.0.113.80) smtp.mailfrom=bad.example; dkim=none (message not signed) header.d=none;dmarc=fail action=quarantine header.from=bad.example;compauth=fail reason=000');
    expect(ar.authservId).toBe('');
    expect(ar.results.map((r) => `${r.method}=${r.result}`)).toEqual(['spf=fail', 'dkim=none', 'dmarc=fail', 'compauth=fail']);
    expect(ar.results[3].props['reason']).toBe('000');
    expect(ar.results[1].domain).toBeNull();
  });
  it('trusts only the topmost header, computes alignment and reads ARC', () => {
    const report = buildAuthReport({
      authResults: ['mx.example.net; spf=pass smtp.mailfrom=news.shop.example; dkim=pass header.d=other.example', 'forged.example; dmarc=pass header.from=shop.example'],
      arcAuthResults: ['i=1; lists.example; spf=fail smtp.mailfrom=shop.example', 'i=2; mx.example; arc=pass'],
      arcSeals: ['i=1; a=rsa-sha256; cv=none; d=lists.example', 'i=2; a=rsa-sha256; cv=pass; d=mx.example'],
      receivedSpf: null,
      fromDomain: 'shop.example',
    });
    expect(report.primary?.authservId).toBe('mx.example.net');
    expect(report.earlier).toHaveLength(1);
    expect(report.alignment).toEqual({ fromDomain: 'shop.example', spfAligned: true, dkimAligned: false });
    expect(report.arc.map((a) => a.instance)).toEqual([2, 1]);
    expect(report.arcChain).toBe('pass');
  });
});
