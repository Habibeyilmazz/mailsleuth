// The result page, shared by the web app and the browser extension. Everything from the email goes in as text (see dom.ts).
import type { Address } from '../core/address';
import type { Analysis, Finding } from '../core/analyze';
import { escapeJsonControls } from '../core/encoding';
import { toUnicodeDomain } from '../core/punycode';
import { defang, formatBytes, formatDelay, formatUtc, toMarkdown } from '../core/report';
import { h, type Child } from './dom';

export interface Entry { label: string; analysis: Analysis }

const SEVERITY_LABEL: Record<Finding['severity'], string> = { high: 'High', medium: 'Medium', low: 'Low', info: 'Note' };
const LEVEL_LABEL: Record<Analysis['level'], string> = { high: 'High risk', suspicious: 'Suspicious', low: 'Low risk' };

function addr(a: Address | null | undefined): string {
  if (!a) return '—';
  return a.name ? `${a.name} <${a.address}>` : a.address;
}

function section(id: string, title: string, intro: string | null, ...body: Child[]) {
  return h('section', { class: 'panel', id, 'aria-labelledby': `${id}-h` }, h('h2', { id: `${id}-h` }, title), intro && h('p', { class: 'intro' }, intro), ...body);
}

// A hostile email can carry hundreds of thousands of headers, hops or links; rendering them all locks the tab.
const MAX_ROWS = 200;
const shown = <T,>(items: T[]) => items.slice(0, MAX_ROWS);
const more = (items: unknown[]) =>
  items.length > MAX_ROWS && h('p', { class: 'note' }, `${items.length - MAX_ROWS} more not shown here. "Copy JSON report" includes all of them.`);

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
          f.evidence.length > 0 && h('ul', { class: 'evidence' }, shown(f.evidence).map((e) => h('li', {}, e))),
          more(f.evidence),
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
    h('ol', { class: 'timeline' }, shown(a.hops).map((hop) =>
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
      ))),
    more(a.hops));
}

function renderLinks(a: Analysis) {
  if (!a.links.length) return section('links', 'Links', null, h('p', { class: 'empty' }, 'No links found.'));
  return section('links', 'Links', 'Shown defanged (hxxp, [.]) so nothing here is clickable. Lookup buttons send only that link to the named service.',
    h('ul', { class: 'links' }, shown(a.links).map((l) => {
      const issues = [...l.issues.map((i) => i.detail), ...l.domainIssues.map((i) => i.detail)];
      const web = /^https?:/i.test(l.finalUrl);
      return h('li', { class: issues.length ? 'link flagged' : 'link' },
        l.text !== null && h('p', { class: 'link-text' }, l.text ? `“${l.text}”` : '(no visible text)'),
        h('p', { class: 'mono url' }, defang(l.finalUrl)),
        l.attachment !== null && h('p', { class: 'small' }, 'Inside the attachment ', h('span', { class: 'mono' }, l.attachment)),
        l.unwrappedVia.length > 0 && h('p', { class: 'small' }, `Unwrapped from ${l.unwrappedVia.join(' → ')}. Original: `, h('span', { class: 'mono' }, defang(l.href))),
        issues.length > 0 && h('ul', { class: 'issues' }, issues.map((i) => h('li', {}, i))),
        h('p', { class: 'actions' },
          copyButton(l.finalUrl, 'Copy URL'),
          web && lookup('VirusTotal', `https://www.virustotal.com/gui/search/${encodeURIComponent(l.finalUrl)}`, 'URL'),
          web && l.host && lookup('URLhaus', `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(l.host)}`, 'host name'),
        ),
      );
    })),
    more(a.links));
}

// Files inside an attached ZIP are labelled "archive.zip › entry".
const linksIn = (a: Analysis, filename: string) => a.links.filter((l) => l.attachment === filename || l.attachment?.startsWith(`${filename} › `)).length;

function renderAttachments(a: Analysis, open: (e: Entry) => void) {
  if (!a.attachments.length) return section('attachments', 'Attachments', null, h('p', { class: 'empty' }, 'No attachments.'));
  return section('attachments', 'Attachments', 'Inspected by their internal structure, never opened or run. Hashes let you look a file up without uploading it.',
    h('ul', { class: 'atts' }, shown(a.attachments).map((att) =>
      h('li', { class: att.issues.length ? 'att flagged' : 'att' },
        h('p', { class: 'att-name' }, h('strong', { class: 'mono' }, att.filename), ` ${formatBytes(att.size)}`),
        h('p', { class: 'small' }, `Declared as ${att.contentType}${att.detectedType ? `; content looks like ${att.detectedType}` : ''}`),
        h('p', { class: 'mono hash' }, `SHA-256 ${att.sha256}`),
        att.zipEntries.length > 0 && h('details', {}, h('summary', {}, `${att.zipEntries.length} file${att.zipEntries.length === 1 ? '' : 's'} inside`), h('ul', { class: 'mono small' }, shown(att.zipEntries).map((n) => {
          const hash = att.zipHashes.find((z) => z.name === n)?.sha256;
          return h('li', {}, n, hash && h('span', { class: 'hash' }, `SHA-256 ${hash}`));
        })), more(att.zipEntries)),
        linksIn(a, att.filename) > 0 && h('p', { class: 'small' }, `${linksIn(a, att.filename)} link${linksIn(a, att.filename) === 1 ? '' : 's'} inside, listed under Links`),
        att.issues.length > 0 && h('ul', { class: 'issues' }, att.issues.map((i) => h('li', {}, i.detail))),
        h('p', { class: 'actions' },
          copyButton(att.sha256, 'Copy hash'),
          lookup('VirusTotal', `https://www.virustotal.com/gui/file/${att.sha256}`, 'hash'),
          lookup('MalwareBazaar', `https://bazaar.abuse.ch/browse.php?search=sha256%3A${att.sha256}`, 'hash'),
          att.email && h('button', {
            type: 'button',
            class: 'primary small',
            onclick: () => open({ label: att.filename, analysis: att.email! }),
          }, 'Analyze attached email'),
        ),
      ))),
    more(a.attachments));
}

function renderRaw(a: Analysis) {
  return section('raw', 'Structure and headers', null,
    h('details', {}, h('summary', {}, `MIME structure (${a.structure.length} part${a.structure.length === 1 ? '' : 's'})`),
      h('ul', { class: 'tree mono small' }, shown(a.structure).map((p) => {
        const li = h('li', {}, `${p.contentType}${p.filename ? `  “${p.filename}”` : ''}${p.size ? `  ${formatBytes(p.size)}` : ''}`);
        li.style.paddingLeft = `${p.depth * 1.25}rem`;
        return li;
      })), more(a.structure)),
    h('details', {}, h('summary', {}, `All headers (${a.headers.length})`),
      h('dl', { class: 'headers mono small' }, shown(a.headers).map((x) => [h('dt', {}, x.name), h('dd', {}, x.value)])), more(a.headers)),
    a.bodyText && h('details', {}, h('summary', {}, 'Message text (as plain text, links not clickable)'), h('pre', { class: 'body', tabindex: '0', 'aria-label': 'Message text' }, a.bodyText)),
  );
}

/** Shows an analysis in root, with a breadcrumb for attached emails the user opens. onReset adds "Analyze another email". */
export function showReport(root: HTMLElement, first: Entry, onReset?: () => void) {
  /** Breadcrumb of analyses: outer email first, then any attached email the user opened. */
  let stack = [first];
  const render = () => {
    const current = stack[stack.length - 1];
    const a = current.analysis;
    const crumbs = h('nav', { class: 'crumbs', 'aria-label': 'Analyzed messages' },
      stack.map((s, i) => i === stack.length - 1
        ? h('span', { 'aria-current': 'page' }, s.label)
        : [h('button', { type: 'button', class: 'link-button', onclick: () => { stack = stack.slice(0, i + 1); render(); } }, s.label), h('span', { 'aria-hidden': 'true' }, ' / ')]),
    );
    const toolbar = h('div', { class: 'toolbar' },
      crumbs,
      h('span', { class: 'spacer' }),
      copyButton(toMarkdown(a), 'Copy Markdown report'),
      copyButton(escapeJsonControls(JSON.stringify(a, null, 2)), 'Copy JSON report'),
      onReset && h('button', { type: 'button', class: 'ghost small', onclick: onReset }, 'Analyze another email'),
    );
    const open = (e: Entry) => { stack.push(e); render(); };
    root.replaceChildren(
      h('h1', { class: 'sr-only' }, `Analysis of ${current.label}`),
      toolbar,
      h('div', { class: 'layout' },
        h('div', { class: 'col-verdict', tabindex: '0', role: 'region', 'aria-label': 'Verdict and next steps' }, renderVerdict(a)),
        h('div', { class: 'col-detail' }, renderFindings(a), renderSender(a), renderAuth(a), renderHops(a), renderLinks(a), renderAttachments(a, open), renderRaw(a)),
      ),
    );
    root.hidden = false;
    (root.querySelector('#verdict-h') as HTMLElement).focus();
    window.scrollTo({ top: 0 });
  };
  render();
}
