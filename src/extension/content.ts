// Content script on mail.google.com: adds "Check with mailsleuth" to each open message, downloads that
// message's raw source with the tab's own session (same request as Gmail's "Download message"), and hands
// the bytes to the extension's panel page in an iframe, which analyzes and renders them. This script never
// parses or renders anything from the email itself.
import { fetchRawMessage, MESSAGE_SELECTOR, messageQuery, placeBar, rawMessageUrl } from './gmail';

declare const chrome: { runtime: { getURL(path: string): string } };
// Firefox content scripts: content.fetch sends the request as the page (same origin, Gmail's cookies); plain fetch would not.
declare const content: { fetch: typeof fetch } | undefined;
const pageFetch: typeof fetch = typeof content !== 'undefined' && content?.fetch ? content.fetch.bind(content) : fetch;

const PANEL_URL = chrome.runtime.getURL('panel.html#gmail');
const EXT_ORIGIN = new URL(PANEL_URL).origin;
const MARK = 'data-mailsleuth';

let frame: HTMLIFrameElement | null = null;
let frameReady: Promise<void> = Promise.resolve();
let lastButton: HTMLButtonElement | null = null;
let ticket = 0;

function openPanel(): HTMLIFrameElement {
  if (frame?.isConnected) return frame;
  frame = document.createElement('iframe');
  frame.src = PANEL_URL;
  frame.title = 'mailsleuth result';
  frame.allow = 'clipboard-write'; // the panel's "Copy report" buttons
  frame.style.cssText = 'position:fixed;top:0;right:0;width:min(480px,100vw);height:100vh;border:0;border-left:1px solid #d5dbe2;' +
    'box-shadow:-12px 0 32px rgba(24,33,44,.18);z-index:2147483646;background:#eef1f4;color-scheme:normal';
  const f = frame;
  frameReady = new Promise((done) => f.addEventListener('load', () => done(), { once: true }));
  document.body.append(f);
  return f;
}

function closePanel() {
  frame?.remove();
  frame = null;
  lastButton?.focus();
}

async function check(query: string, button: HTMLButtonElement) {
  const mine = ++ticket;
  lastButton = button;
  const f = openPanel();
  await frameReady;
  const post = (msg: object, transfer: Transferable[] = []) => f.contentWindow?.postMessage(msg, EXT_ORIGIN, transfer);
  post({ type: 'loading' });
  try {
    const bytes = await fetchRawMessage(rawMessageUrl(location, query), pageFetch);
    if (mine === ticket) post({ type: 'raw', bytes }, [bytes]);
  } catch (e) {
    if (mine === ticket) post({ type: 'error', message: (e as Error).message });
  }
}

window.addEventListener('message', (e) => {
  if (e.origin === EXT_ORIGIN && frame && e.source === frame.contentWindow && e.data?.type === 'close') closePanel();
});

// Solid blue with white text (6.6:1 contrast) stands out on both Gmail's light and dark themes.
const style = document.createElement('style');
style.textContent = `.mailsleuth-chip{display:inline-flex;align-items:center;gap:5px;height:24px;padding:0 10px 0 8px;margin:0;
font:500 12px/1 "Google Sans",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:#fff;background:#0b57d0;
border:0;border-radius:999px;cursor:pointer;box-shadow:0 1px 2px rgba(0,0,0,.25)}
.mailsleuth-chip:hover{background:#0842a0}
.mailsleuth-chip:focus-visible{outline:2px solid #a8c7fa;outline-offset:2px}`;
document.head.append(style);

function shieldIcon(): SVGSVGElement {
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', '14');
  svg.setAttribute('height', '14');
  svg.setAttribute('aria-hidden', 'true');
  const path = document.createElementNS(NS, 'path');
  path.setAttribute('d', 'M12 3 5 6v5c0 4.4 3 8.3 7 9.5 4-1.2 7-5.1 7-9.5V6z M9 12l2 2 4-4');
  path.setAttribute('fill', 'none');
  path.setAttribute('stroke', 'currentColor');
  path.setAttribute('stroke-width', '2');
  path.setAttribute('stroke-linecap', 'round');
  path.setAttribute('stroke-linejoin', 'round');
  svg.append(path);
  return svg;
}

function addButtons() {
  for (const message of document.querySelectorAll(MESSAGE_SELECTOR)) {
    if (message.querySelector(`[${MARK}]`)) continue;
    const query = messageQuery(message);
    if (!query) continue;
    const bar = document.createElement('span');
    bar.setAttribute(MARK, '');
    bar.style.cssText = 'display:inline-flex;vertical-align:middle;margin-left:10px;flex:none';
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'mailsleuth-chip';
    button.setAttribute('aria-label', 'Check with mailsleuth');
    button.title = 'Check this email for phishing signs (mailsleuth, offline)';
    button.append(shieldIcon(), 'Check with mailsleuth');
    // The chip sits in Gmail's header, where a click would also collapse the message.
    for (const type of ['mousedown', 'mouseup', 'click']) button.addEventListener(type, (e) => e.stopPropagation());
    button.addEventListener('click', () => void check(query, button));
    bar.append(button);
    placeBar(message, bar);
  }
}

// Gmail swaps conversations in and out without reloading; look again after changes, at most once per frame.
let queued = false;
new MutationObserver(() => {
  if (queued) return;
  queued = true;
  requestAnimationFrame(() => {
    queued = false;
    addButtons();
  });
}).observe(document.body, { childList: true, subtree: true });
addButtons();
