// @vitest-environment happy-dom
// The Gmail side of the browser extension, on a saved synthetic page (test/fixtures/gmail/thread.html).
import { readFileSync } from 'node:fs';
import { beforeEach, describe, expect, it } from 'vitest';
import { analyze } from '../src/core/analyze';
import { bytesToBinary } from '../src/core/encoding';
import { fetchRawMessage, MESSAGE_SELECTOR, messageQuery, placeBar, rawMessageUrl } from '../src/extension/gmail';

const read = (path: string) => readFileSync(new URL(path, import.meta.url));
const GMAIL = { origin: 'https://mail.google.com', pathname: '/mail/u/0/' };

beforeEach(() => {
  document.documentElement.innerHTML = read('./fixtures/gmail/thread.html').toString().replace(/^[\s\S]*?<html[^>]*>/, '');
});

describe('Gmail message ids', () => {
  it('finds each open message and names it the way Gmail\'s download link does', () => {
    const queries = [...document.querySelectorAll(MESSAGE_SELECTOR)].map(messageQuery);
    expect(queries).toEqual(['permmsgid=msg-f:1790000000000000042', 'th=18d6f5c2a4b3e001', null]);
  });

  it('refuses ids that could add parameters to the URL', () => {
    const el = document.createElement('div');
    for (const bad of ['#msg-f:1&view=om', 'msg-f:12 34', 'thread-f:1', '#msg-f:', 'msg-f:1#x', 'msg-f:1/../x']) {
      el.setAttribute('data-message-id', bad);
      expect(messageQuery(el)).toBeNull();
    }
    el.removeAttribute('data-message-id');
    el.setAttribute('data-legacy-message-id', '18d6f5c2a4b3e001&x=1');
    expect(messageQuery(el)).toBeNull();
    el.setAttribute('data-message-id', '#msg-a:r-4617284752868375338'); // mail you sent
    expect(messageQuery(el)).toBe('permmsgid=msg-a:r-4617284752868375338');
  });

  it('builds the download URL for the account in the tab', () => {
    expect(rawMessageUrl(GMAIL, 'permmsgid=msg-f:42')).toBe('https://mail.google.com/mail/u/0/?view=att&permmsgid=msg-f:42&attid=0&disp=comp&safe=1&zw');
    expect(rawMessageUrl({ ...GMAIL, pathname: '/mail/u/3/' }, 'th=ab')).toBe('https://mail.google.com/mail/u/3/?view=att&th=ab&attid=0&disp=comp&safe=1&zw');
    expect(rawMessageUrl({ ...GMAIL, pathname: '/mail/' }, 'th=ab')).toBe('https://mail.google.com/mail/?view=att&th=ab&attid=0&disp=comp&safe=1&zw');
    // Any other path (a popout, a future layout) falls back to the first account rather than guessing.
    expect(rawMessageUrl({ ...GMAIL, pathname: '/mail/u/0/popout' }, 'th=ab')).toBe('https://mail.google.com/mail/u/0/?view=att&th=ab&attid=0&disp=comp&safe=1&zw');
  });
});

describe('where the Check chip goes', () => {
  it('joins the sender line when there is one, else goes first without stretching', () => {
    const [withSender, rowLayout] = document.querySelectorAll(MESSAGE_SELECTOR);
    const a = document.createElement('span');
    placeBar(withSender, a);
    expect(a.parentElement?.tagName).toBe('H3');
    expect(a.parentElement?.querySelector('[email]')?.textContent).toBe('Voice Mail');
    const b = document.createElement('span');
    placeBar(rowLayout, b);
    expect(rowLayout.firstElementChild).toBe(b);
    expect(b.style.alignSelf).toBe('flex-start');
  });
});

describe('from the button to the result', () => {
  const sample = read('../samples/10-voicemail-zip.eml');
  // finalUrl: where the response ended up after redirects (Response.url), as the browser reports it.
  const fakeGmail = (body: BodyInit, status = 200, finalUrl = '') => {
    const calls: { url: string; init?: RequestInit }[] = [];
    const fn = (async (url: string, init?: RequestInit) => {
      calls.push({ url, init });
      const res = new Response(body, { status });
      Object.defineProperty(res, 'url', { value: finalUrl });
      return res;
    }) as typeof fetch;
    return { fn, calls };
  };

  it('downloads the open message through Gmail\'s redirect and rates it like the CLI', async () => {
    const message = document.querySelector(MESSAGE_SELECTOR)!;
    const gmail = fakeGmail(sample, 200, 'https://mail-attachment.googleusercontent.com/attachment/u/0/?x=1');
    const bytes = await fetchRawMessage(rawMessageUrl(GMAIL, messageQuery(message)!), gmail.fn);
    expect(gmail.calls).toHaveLength(1);
    expect(gmail.calls[0].url).toMatch(/^https:\/\/mail\.google\.com\/mail\/u\/0\/\?view=att&permmsgid=msg-f:1790000000000000042&attid=0&disp=comp&safe=1&zw&ms=\d+$/);
    expect(gmail.calls[0].init).toMatchObject({ mode: 'cors', credentials: 'same-origin' });

    const viaGmail = await analyze(bytesToBinary(new Uint8Array(bytes)));
    const direct = await analyze(bytesToBinary(new Uint8Array(sample)));
    expect(viaGmail.score).toBe(direct.score);
    expect(viaGmail.findings.map((f) => f.id)).toEqual(direct.findings.map((f) => f.id));
    expect(viaGmail.attachments[0].sha256).toBe(direct.attachments[0].sha256);
    expect(viaGmail.level).toBe('high');
  });

  it('refuses a sign-in page, an error and an empty answer instead of rating them', async () => {
    await expect(fetchRawMessage('u', fakeGmail('\n<!DOCTYPE html><html><title>Sign in</title>').fn)).rejects.toThrow(/web page instead of the message/);
    await expect(fetchRawMessage('u', fakeGmail('<html><body>x').fn)).rejects.toThrow(/web page/);
    await expect(fetchRawMessage('u', fakeGmail('nope', 404).fn)).rejects.toThrow(/answered 404/);
    await expect(fetchRawMessage('u', fakeGmail(' \r\n').fn)).rejects.toThrow(/empty/);
  });

  it('refuses a body that came from any host but Gmail\'s two', async () => {
    await expect(fetchRawMessage('u', fakeGmail(sample, 200, 'https://evil.example/x').fn)).rejects.toThrow(/somewhere unexpected/);
  });
});
