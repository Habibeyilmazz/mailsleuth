// The extension's one page. panel.html#gmail: the panel inside Gmail, fed the raw message by content.ts.
// panel.html?popup / panel.html: the toolbar popup or a tab, where you drop or choose an .eml/.msg file.
import '../web/style.css';
import './panel.css';
import { analyze, MAX_INPUT_BYTES } from '../core/analyze';
import { bytesToBinary } from '../core/encoding';
import { showReport } from '../web/view';

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const status = $<HTMLParagraphElement>('status');
const results = $<HTMLElement>('results');
const intake = $<HTMLElement>('intake');
const fileInput = $<HTMLInputElement>('file');
const dropzone = $<HTMLLabelElement>('dropzone');

const inGmail = location.hash === '#gmail';
let runs = 0;

function say(text: string, error = false) {
  status.textContent = text;
  status.classList.toggle('is-error', error);
}

/** Analyzes raw message bytes and shows the result. label null: use the email's subject. */
async function show(bytes: ArrayBuffer | Promise<ArrayBuffer>, label: string | null) {
  const ticket = ++runs;
  results.hidden = true;
  say('Analyzing…');
  try {
    const buf = await bytes;
    if (buf.byteLength > MAX_INPUT_BYTES) throw new Error(`it is larger than ${MAX_INPUT_BYTES / 1024 / 1024} MB`);
    const analysis = await analyze(bytesToBinary(new Uint8Array(buf)));
    if (ticket !== runs) return;
    say('');
    intake.hidden = true;
    showReport(results, { label: label ?? (analysis.summary.subject || 'This email'), analysis }, inGmail ? undefined : reset);
  } catch (e) {
    if (ticket === runs) say(`Could not analyze this email: ${(e as Error).message}`, true);
  }
}

function reset() {
  runs++;
  results.hidden = true;
  results.replaceChildren();
  intake.hidden = false;
  fileInput.value = '';
  fileInput.focus();
}

if (inGmail) {
  document.body.classList.add('in-gmail');
  const close = $<HTMLButtonElement>('close');
  close.hidden = false;
  const requestClose = () => parent.postMessage({ type: 'close' }, 'https://mail.google.com');
  close.addEventListener('click', requestClose);
  addEventListener('keydown', (e) => e.key === 'Escape' && requestClose());
  // Only Gmail's top window (where content.ts runs) may hand us a message; anything else is ignored.
  addEventListener('message', (e) => {
    if (e.source !== parent || e.origin !== 'https://mail.google.com') return;
    const msg = e.data as { type: string; bytes?: ArrayBuffer; message?: string };
    if (msg.type === 'loading') {
      runs++;
      results.hidden = true;
      say('Downloading this message from Gmail…');
    } else if (msg.type === 'raw' && msg.bytes instanceof ArrayBuffer) void show(msg.bytes, null);
    else if (msg.type === 'error') {
      runs++;
      say(String(msg.message), true);
    }
  });
} else {
  intake.hidden = false;
  if (location.search === '?popup') {
    document.body.classList.add('popup');
    $('in-tab').hidden = false;
  }
  const pick = (f: File | undefined) => f && void show(f.arrayBuffer(), f.name);
  fileInput.addEventListener('change', () => pick(fileInput.files?.[0]));
  for (const ev of ['dragenter', 'dragover'] as const) {
    dropzone.addEventListener(ev, (e) => {
      e.preventDefault();
      dropzone.classList.add('is-over');
    });
  }
  for (const ev of ['dragleave', 'drop'] as const) dropzone.addEventListener(ev, () => dropzone.classList.remove('is-over'));
  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    pick(e.dataTransfer?.files[0]);
  });
  // Dropping outside the zone must not navigate away from the page.
  addEventListener('dragover', (e) => e.preventDefault());
  addEventListener('drop', (e) => e.preventDefault());
}
