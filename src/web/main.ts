import './style.css';
import { analyze, MAX_INPUT_BYTES } from '../core/analyze';
import { bytesToBinary, textToBinary } from '../core/encoding';
import { h } from './dom';
import { showReport } from './view';

const EML_SAMPLES = import.meta.glob('../../samples/*.eml', { query: '?raw', import: 'default', eager: true }) as Record<string, string>;
// .msg is binary: inlined as a data: URL (base64), which decodes straight to a byte-per-character string.
const MSG_SAMPLES = import.meta.glob('../../samples/*.msg', { query: '?inline', import: 'default', eager: true }) as Record<string, string>;
const SAMPLES: Record<string, () => string> = {
  ...Object.fromEntries(Object.entries(EML_SAMPLES).map(([p, text]) => [p, () => textToBinary(text)])),
  ...Object.fromEntries(Object.entries(MSG_SAMPLES).map(([p, url]) => [p, () => atob(url.slice(url.indexOf(',') + 1))])),
};
const SAMPLE_LABELS: Record<string, string> = {
  '01-paypal-lookalike.eml': 'PayPal look-alike (credential phishing)',
  '02-invoice-macro.eml': 'Invoice with macro document',
  '03-newsletter-legit.eml': 'Ordinary newsletter (legitimate)',
  '04-ceo-gift-cards.eml': 'CEO gift-card request (BEC)',
  '05-parcel-redelivery.eml': 'Parcel redelivery link tricks',
  '06-user-report-forwarded.eml': 'User report with phishing attached',
  '07-outlook-sign-request.msg': 'Outlook .msg file: fake signature request',
  '08-pdf-link-lure.eml': 'Calm email, the link is in the PDF',
  '09-contract-remote-template.eml': 'Contract that loads a remote template',
  '10-voicemail-zip.eml': 'Voicemail ZIP with a sign-in page inside',
};

const $ = <T extends HTMLElement>(sel: string) => document.querySelector(sel) as T;
const fileInput = $<HTMLInputElement>('#file');
const dropzone = $<HTMLLabelElement>('#dropzone');
const paste = $<HTMLTextAreaElement>('#paste');
const sampleSelect = $<HTMLSelectElement>('#sample');
const status = $<HTMLParagraphElement>('#status');
const results = $<HTMLElement>('#results');
const intake = $<HTMLElement>('#intake');

for (const path of Object.keys(SAMPLES).sort()) {
  const name = path.split('/').pop()!;
  sampleSelect.append(h('option', { value: path }, SAMPLE_LABELS[name] ?? name));
}

const TOO_BIG = `That input is larger than ${MAX_INPUT_BYTES / 1024 / 1024} MB. Emails are almost never that big; check you picked the right file.`;

let runs = 0;

function say(text: string, error = false) {
  status.textContent = text;
  status.classList.toggle('is-error', error);
}

/** input is a byte-per-character string, or a File still to be read. */
async function run(input: string | File, label: string) {
  const ticket = ++runs; // taken before any await, so a slow file read cannot overwrite a newer result
  const size = typeof input === 'string' ? input.length : input.size;
  if (size > MAX_INPUT_BYTES) {
    say(TOO_BIG, true);
    return;
  }
  say('Analyzing…');
  try {
    const binary = typeof input === 'string' ? input : bytesToBinary(new Uint8Array(await input.arrayBuffer()));
    if (ticket !== runs) return;
    if (!binary.trim()) {
      say('Nothing to analyze yet: drop an .eml or .msg file, paste the message source, or pick a sample.', true);
      if (typeof input === 'string') paste.focus();
      return;
    }
    // Let "Analyzing…" paint before the synchronous parse, so a click on a big paste answers at once.
    await new Promise((done) => requestAnimationFrame(() => setTimeout(done)));
    if (ticket !== runs) return;
    const analysis = await analyze(binary);
    if (ticket !== runs) return; // the user already started another analysis
    say('');
    intake.classList.add('compact');
    showReport(results, { label, analysis }, reset);
  } catch (e) {
    if (ticket === runs) say(`Could not ${typeof input === 'string' ? 'analyze this input' : `read ${input.name}`}: ${(e as Error).message}`, true);
  }
}

fileInput.addEventListener('change', () => fileInput.files?.[0] && run(fileInput.files[0], fileInput.files[0].name));
for (const ev of ['dragenter', 'dragover'] as const) {
  dropzone.addEventListener(ev, (e) => {
    e.preventDefault();
    dropzone.classList.add('is-over');
  });
}
for (const ev of ['dragleave', 'drop'] as const) dropzone.addEventListener(ev, () => dropzone.classList.remove('is-over'));
dropzone.addEventListener('drop', (e) => {
  e.preventDefault();
  const file = e.dataTransfer?.files[0];
  if (file) void run(file, file.name);
});
// Dropping outside the zone must not navigate away and lose the page.
window.addEventListener('dragover', (e) => e.preventDefault());
window.addEventListener('drop', (e) => e.preventDefault());

$('#analyze-paste').addEventListener('click', () => run(textToBinary(paste.value), 'Pasted message'));
paste.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    void run(textToBinary(paste.value), 'Pasted message');
  }
});
$('#load-sample').addEventListener('click', () => {
  const path = sampleSelect.value;
  run(SAMPLES[path](), path.split('/').pop()!);
});

function reset() {
  runs++; // drop any analysis still in flight
  results.hidden = true;
  results.replaceChildren();
  intake.classList.remove('compact');
  fileInput.value = '';
  paste.value = '';
  fileInput.focus();
}
