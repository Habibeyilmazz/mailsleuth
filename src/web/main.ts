import './style.css';
import type { Address } from '../core/address';
import { analyze, MAX_INPUT_BYTES, type Analysis, type Finding } from '../core/analyze';
import { bytesToBinary, textToBinary } from '../core/encoding';
import { toUnicodeDomain } from '../core/punycode';
import { defang, formatBytes, formatDelay, formatUtc, h, type Child } from './dom';

const SAMPLES = import.meta.glob('../../samples/*.eml', { query: '?raw', import: 'default', eager: true }) as Record<string, string>;
const SAMPLE_LABELS: Record<string, string> = {
  '01-paypal-lookalike.eml': 'PayPal look-alike (credential phishing)',
  '02-invoice-macro.eml': 'Invoice with macro document',
  '03-newsletter-legit.eml': 'Ordinary newsletter (legitimate)',
  '04-ceo-gift-cards.eml': 'CEO gift-card request (BEC)',
  '05-parcel-redelivery.eml': 'Parcel redelivery link tricks',
  '06-user-report-forwarded.eml': 'User report with phishing attached',
};

const $ = <T extends HTMLElement>(sel: string) => document.querySelector(sel) as T;
const fileInput = $<HTMLInputElement>('#file');
const dropzone = $<HTMLLabelElement>('#dropzone');
const paste = $<HTMLTextAreaElement>('#paste');
const sampleSelect = $<HTMLSelectElement>('#sample');
const status = $<HTMLParagraphElement>('#status');
const results = $<HTMLElement>('#results');
const intake = $<HTMLElement>('#intake');

/** Breadcrumb of analyses: outer email first, then any attached email the user opened. */
let stack: { label: string; analysis: Analysis }[] = [];

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

async function run(binary: string, label: string) {
  if (binary.length > MAX_INPUT_BYTES) {
    say(TOO_BIG, true);
    return;
  }
  if (!binary.trim()) {
    say('Nothing to analyze yet: drop an .eml file, paste the message source, or pick a sample.', true);
    paste.focus();
    return;
  }
  say('Analyzing…');
  const ticket = ++runs;
  try {
    const analysis = await analyze(binary);
    if (ticket !== runs) return; // the user already started another analysis
    stack = [{ label, analysis }];
    say('');
    render();
  } catch (e) {
    say(`Could not analyze this input: ${(e as Error).message}`, true);
  }
}

async function runFile(file: File) {
  if (file.size > MAX_INPUT_BYTES) {
    say(TOO_BIG, true);
    return;
  }
  await run(bytesToBinary(new Uint8Array(await file.arrayBuffer())), file.name);
}

fileInput.addEventListener('change', () => fileInput.files?.[0] && runFile(fileInput.files[0]));
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
  if (file) void runFile(file);
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
  run(textToBinary(SAMPLES[path]), path.split('/').pop()!);
});

// ---------- rendering ----------

const SEVERITY_LABEL: Record<Finding['severity'], string> = { high: 'High', medium: 'Medium', low: 'Low', info: 'Note' };
const LEVEL_LABEL: Record<Analysis['level'], string> = { high: 'High risk', suspicious: 'Suspicious', low: 'Low risk' };

function addr(a: Address | null | undefined): string {
  if (!a) return '—';
  return a.name ? `${a.name} <${a.address}>` : a.address;
}

function section(id: string, title: string, intro: string | null, ...body: Child[]) {
  return h('section', { class: 'panel', id, 'aria-labelledby': `${id}-h` }, h('h2', { id: `${id}-h` }, title), intro && h('p', { class: 'intro' }, intro), ...body);
}

function lookup(label: string, href: string, what: string) {
  return h('a', { class: 'lookup', href, target: '_blank', rel: 'noopener noreferrer', title: `Opens ${label} in a new tab and sends it only this ${what}` }, label);
}

function copyButton(value: string, label = 'Copy') {
  return h('button', {
    type: 'button',
    class: 'ghost small',
    'aria-live': 'polite',
    onclick: async (e: Event) => {
      const btn = e.currentTarget as HTMLButtonElement;
      try {
        await navigator.clipboard.writeText(value);
        btn.textContent = 'Copied';
      } catch {
        btn.textContent = 'Copy failed';
      }
      setTimeout(() => (btn.textContent = label), 1500);
    },
  }, label);
}

function renderVerdict(a: Analysis) {
  const scored = a.findings.filter((f) => f.points > 0);
  const total = scored.reduce((s, f) => s + f.points, 0);
  const scale = total > 100 ? 100 / total : 1;
  return h('section', { class: `verdict level-${a.level}`, 'aria-labelledby': 'verdict-h' },
    h('div', { class: 'verdict-top' },
      h('p', { class: 'score' }, h('span', { class: 'sr-only' }, `Risk score ${a.score} out of 100`), h('span', { class: 'score-n', 'aria-hidden': 'true' }, a.score), h('span', { class: 'score-of', 'aria-hidden': 'true' }, '/100')),
      h('div', {},
        h('h2', { id: 'verdict-h', tabindex: '-1' }, LEVEL_LABEL[a.level]),
        h('p', { class: 'verdict-text' }, a.verdict),
      ),
    ),
    h('div', { class: 'bar', 'aria-hidden': 'true' },
      scored.map((f) => {
        const seg = h('span', { class: `seg sev-${f.severity}`, title: `${f.title} (+${f.points})` });
        seg.style.width = `${f.points * scale}%`;
        return seg;
      }),
    ),
    h('p', { class: 'bar-legend' }, scored.length ? `Each block is one reason below; wider blocks weigh more. High +25, medium +12, low +5, capped at 100.` : 'No reason added any points.'),
    h('p', { class: 'caveat' }, 'This is a set of warning signs, not a verdict of guilt or innocence. Attackers can pass every check, and legitimate mail can trip some.'),
    h('h3', {}, 'What to do next'),
    h('ol', { class: 'steps' }, a.nextSteps.map((s) => h('li', {}, s))),
  );
}

function renderFindings(a: Analysis) {
  const list = a.findings.length
    ? h('ul', { class: 'findings' }, a.findings.map((f) =>
        h('li', { class: `finding sev-${f.severity}` },
          h('div', { class: 'finding-head' },
            h('span', { class: 'badge' }, SEVERITY_LABEL[f.severity]),
            h('h3', {}, f.title),
            h('span', { class: 'points' }, f.points ? `+${f.points}` : ''),
          ),
          h('p', {}, f.explanation),
          f.evidence.length > 0 && h('ul', { class: 'evidence' }, f.evidence.map((e) => h('li', {}, e))),
        )))
    : h('p', { class: 'empty' }, 'No warning signs were found by any check.');
  return section('reasons', 'Reasons', null, list,
    a.reassurances.length > 0 && h('div', { class: 'reassure' }, h('h3', {}, 'Points in its favour'), h('ul', {}, a.reassurances.map((r) => h('li', {}, r)))));
}

function renderSender(a: Analysis) {
  const s = a.summary;
  const rows: [string, string, string][] = [
    ['From', addr(s.from), 'The sender your mail app shows. Easy to fake on its own.'],
    ['Reply-To', s.replyTo.map(addr).join(', ') || '—', 'Where your reply would go.'],
    ['Return-Path', addr(s.returnPath), 'Hidden envelope sender that receives bounces.'],
    ['Sender', addr(s.sender), 'Who actually submitted it, when different from From.'],
    ['To', s.to.map(addr).join(', ') || '—', ''],
    ['Subject', s.subject || '—', ''],
    ['Date', s.date ?? '—', 'Set by the sender, so it can be anything.'],
  ];
  const idn = [s.from?.domain, ...s.replyTo.map((r) => r.domain)].filter((d): d is string => !!d && /xn--/i.test(d));
  return section('sender', 'Sender', 'Who the message claims to be from, and where replies and bounces really go.',
    h('dl', { class: 'kv' }, rows.filter(([k, v]) => v !== '—' || k === 'From' || k === 'Subject').map(([k, v, hint]) => [
      h('dt', {}, k),
      h('dd', {}, h('span', { class: 'mono' }, v), hint && h('span', { class: 'hint' }, hint)),
    ])),
    idn.length > 0 && h('p', { class: 'note' }, idn.map((d) => `${d} reads as "${toUnicodeDomain(d)}"`).join('; ')),
  );
}

function renderAuth(a: Analysis) {
  const { primary, earlier, arc, arcChain, alignment, receivedSpf } = a.auth;
  if (!primary) {
    return section('auth', 'Authentication', null,
      h('p', { class: 'empty' }, 'No Authentication-Results header was found. Your mail provider adds it on arrival; copy the full original message ("Show original" / "View source") to include it.'),
      receivedSpf && h('p', { class: 'mono small' }, `Received-SPF: ${receivedSpf}`));
  }
  const results = (header: typeof primary) => h('ul', { class: 'auth' }, header.results.map((r) =>
    h('li', { class: `tone-${r.tone}` },
      h('p', { class: 'auth-head' }, h('strong', {}, r.method.toUpperCase()), h('span', { class: 'result' }, r.result), r.domain && h('span', { class: 'mono' }, r.domain)),
      h('p', {}, r.explanation),
    )));
  const intro = a.auth.verified
    ? `Checks run by ${primary.authservId || 'the receiving server'} when the message arrived (the topmost Authentication-Results header, the only one written by your side).`
    : 'These results could not be tied to any receiving server in the delivery path, so anyone could have written them. Treat them as unverified.';
  return section('auth', 'Authentication', intro,
    results(primary),
    alignment.fromDomain && h('p', { class: 'note' },
      `Alignment with the From domain (${alignment.fromDomain}): SPF ${alignment.spfAligned ? 'aligned' : 'not aligned'}, DKIM ${alignment.dkimAligned ? 'aligned' : 'not aligned'}. DMARC needs at least one of them to pass and align.`),
    arc.length > 0 && h('details', {},
      h('summary', {}, `Forwarding record (ARC): ${arc.length} hop${arc.length > 1 ? 's' : ''}, chain ${arcChain ?? 'unknown'}`),
      arc.map((x) => [h('p', { class: 'small' }, `i=${x.instance} by ${x.authservId || 'unknown'}`), results(x)])),
    earlier.length > 0 && h('details', {},
      h('summary', {}, `${earlier.length} earlier Authentication-Results header${earlier.length > 1 ? 's' : ''} (not trustworthy: anyone upstream could write these)`),
      earlier.map((x) => [h('p', { class: 'small' }, x.authservId || 'unknown server'), results(x)])),
  );
}

function renderHops(a: Analysis) {
  if (!a.hops.length) return section('path', 'Delivery path', null, h('p', { class: 'empty' }, 'No Received headers found, so the delivery path is unknown.'));
  return section('path', 'Delivery path', 'Each mail server stamps a Received header. Read top to bottom: from the first server to your inbox. Only the hops added by your own provider (the last ones) are guaranteed genuine.',
    h('ol', { class: 'timeline' }, a.hops.map((hop) =>
      h('li', { class: hop.delaySeconds !== null && hop.delaySeconds < -300 ? 'hop warn' : 'hop' },
        hop.delaySeconds !== null && h('span', { class: 'delay' }, formatDelay(hop.delaySeconds)),
        h('p', { class: 'hop-main' },
          h('span', { class: 'mono' }, hop.from ?? 'unknown'),
          hop.fromIp && h('span', { class: 'mono ip' }, hop.fromIp),
          h('span', { class: 'arrow', 'aria-hidden': 'true' }, ' ⟶ '),
          h('span', { class: 'sr-only' }, ' handed to '),
          h('span', { class: 'mono' }, hop.by ?? 'unknown'),
        ),
        h('p', { class: 'hop-meta' }, [hop.date ? formatUtc(hop.date) : 'no readable date', hop.protocol].filter(Boolean).join(', ')),
        h('details', {}, h('summary', {}, 'Raw header'), h('pre', {}, hop.raw)),
      ))));
}

function renderLinks(a: Analysis) {
  if (!a.links.length) return section('links', 'Links', null, h('p', { class: 'empty' }, 'No links found.'));
  return section('links', 'Links', 'Shown defanged (hxxp, [.]) so nothing here is clickable. Lookup buttons send only that link to the named service.',
    h('ul', { class: 'links' }, a.links.map((l) => {
      const issues = [...l.issues.map((i) => i.detail), ...l.domainIssues.map((i) => i.detail)];
      const web = /^https?:/i.test(l.finalUrl);
      return h('li', { class: issues.length ? 'link flagged' : 'link' },
        l.text !== null && h('p', { class: 'link-text' }, l.text ? `“${l.text}”` : '(no visible text)'),
        h('p', { class: 'mono url' }, defang(l.finalUrl)),
        l.unwrappedVia.length > 0 && h('p', { class: 'small' }, `Unwrapped from ${l.unwrappedVia.join(' → ')}. Original: `, h('span', { class: 'mono' }, defang(l.href))),
        issues.length > 0 && h('ul', { class: 'issues' }, issues.map((i) => h('li', {}, i))),
        h('p', { class: 'actions' },
          copyButton(l.finalUrl, 'Copy URL'),
          web && lookup('VirusTotal', `https://www.virustotal.com/gui/search/${encodeURIComponent(l.finalUrl)}`, 'URL'),
          web && l.host && lookup('URLhaus', `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(l.host)}`, 'host name'),
        ),
      );
    })));
}

function renderAttachments(a: Analysis) {
  if (!a.attachments.length) return section('attachments', 'Attachments', null, h('p', { class: 'empty' }, 'No attachments.'));
  return section('attachments', 'Attachments', 'Inspected by their internal structure, never opened or run. Hashes let you look a file up without uploading it.',
    h('ul', { class: 'atts' }, a.attachments.map((att) =>
      h('li', { class: att.issues.length ? 'att flagged' : 'att' },
        h('p', { class: 'att-name' }, h('strong', { class: 'mono' }, att.filename), ` ${formatBytes(att.size)}`),
        h('p', { class: 'small' }, `Declared as ${att.contentType}${att.detectedType ? `; content looks like ${att.detectedType}` : ''}`),
        h('p', { class: 'mono hash' }, `SHA-256 ${att.sha256}`),
        att.zipEntries.length > 0 && h('details', {}, h('summary', {}, `${att.zipEntries.length} files inside`), h('ul', { class: 'mono small' }, att.zipEntries.slice(0, 200).map((n) => h('li', {}, n)))),
        att.issues.length > 0 && h('ul', { class: 'issues' }, att.issues.map((i) => h('li', {}, i.detail))),
        h('p', { class: 'actions' },
          copyButton(att.sha256, 'Copy hash'),
          lookup('VirusTotal', `https://www.virustotal.com/gui/file/${att.sha256}`, 'hash'),
          lookup('MalwareBazaar', `https://bazaar.abuse.ch/browse.php?search=sha256%3A${att.sha256}`, 'hash'),
          att.email && h('button', {
            type: 'button',
            class: 'primary small',
            onclick: () => {
              stack.push({ label: att.filename, analysis: att.email! });
              render();
            },
          }, 'Analyze attached email'),
        ),
      ))));
}

function renderRaw(a: Analysis) {
  return section('raw', 'Structure and headers', null,
    h('details', {}, h('summary', {}, `MIME structure (${a.structure.length} part${a.structure.length === 1 ? '' : 's'})`),
      h('ul', { class: 'tree mono small' }, a.structure.map((p) => {
        const li = h('li', {}, `${p.contentType}${p.filename ? `  “${p.filename}”` : ''}${p.size ? `  ${formatBytes(p.size)}` : ''}`);
        li.style.paddingLeft = `${p.depth * 1.25}rem`;
        return li;
      }))),
    h('details', {}, h('summary', {}, `All headers (${a.headers.length})`),
      h('dl', { class: 'headers mono small' }, a.headers.map((x) => [h('dt', {}, x.name), h('dd', {}, x.value)]))),
    a.bodyText && h('details', {}, h('summary', {}, 'Message text (as plain text, links not clickable)'), h('pre', { class: 'body' }, a.bodyText)),
  );
}

function render() {
  const current = stack[stack.length - 1];
  const a = current.analysis;
  intake.classList.add('compact');
  const crumbs = h('nav', { class: 'crumbs', 'aria-label': 'Analyzed messages' },
    stack.map((s, i) => i === stack.length - 1
      ? h('span', { 'aria-current': 'page' }, s.label)
      : [h('button', { type: 'button', class: 'link-button', onclick: () => { stack = stack.slice(0, i + 1); render(); } }, s.label), h('span', { 'aria-hidden': 'true' }, ' / ')]),
  );
  const toolbar = h('div', { class: 'toolbar' },
    crumbs,
    h('span', { class: 'spacer' }),
    copyButton(JSON.stringify(a, null, 2), 'Copy JSON report'),
    h('button', { type: 'button', class: 'ghost small', onclick: reset }, 'Analyze another email'),
  );
  results.replaceChildren(
    toolbar,
    h('div', { class: 'layout' },
      h('div', { class: 'col-verdict' }, renderVerdict(a)),
      h('div', { class: 'col-detail' }, renderFindings(a), renderSender(a), renderAuth(a), renderHops(a), renderLinks(a), renderAttachments(a), renderRaw(a)),
    ),
  );
  results.hidden = false;
  ($('#verdict-h') as HTMLElement).focus();
  window.scrollTo({ top: 0 });
}

function reset() {
  stack = [];
  results.hidden = true;
  results.replaceChildren();
  intake.classList.remove('compact');
  fileInput.value = '';
  paste.value = '';
  fileInput.focus();
}
