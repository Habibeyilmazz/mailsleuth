// Markdown report for tickets and chat. Everything from the email is hostile: it goes into code spans
// (never rendered as a link, image, HTML or formatting) and links and domains are defanged.
import type { Address } from './address';
import type { Analysis } from './analyze';
import { revealBidi } from './encoding';

/** Same cap as the page: a hostile email can carry hundreds of thousands of links or hops. */
const MAX_ITEMS = 200;
const LEVEL_LABEL: Record<Analysis['level'], string> = { high: 'High risk', suspicious: 'Suspicious', low: 'Low risk' };
const SEVERITY_LABEL = { high: 'High', medium: 'Medium', low: 'Low', info: 'Note' } as const;

/** hxxps://evil[.]example/path - readable, not clickable, safe to paste into tickets. */
export function defang(url: string): string {
  return url
    .replace(/^http(s?):\/\//i, (_, s: string) => `hxxp${s}://`)
    .replace(/^(hxxps?:\/\/[^/?#]*)/i, (host) => host.replace(/\./g, '[.]'));
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function formatDelay(seconds: number): string {
  const sign = seconds < 0 ? '−' : '+';
  let s = Math.abs(seconds);
  if (s < 60) return `${sign}${s} s`;
  const d = Math.floor(s / 86400);
  s -= d * 86400;
  const hrs = Math.floor(s / 3600);
  s -= hrs * 3600;
  const m = Math.floor(s / 60);
  return sign + [d && `${d} d`, hrs && `${hrs} h`, m && `${m} min`].filter(Boolean).join(' ');
}

export function formatUtc(iso: string): string {
  return iso.replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
}

/** One line, bidi controls shown as markers, other control characters as \uXXXX. */
function oneLine(s: string): string {
  return revealBidi(s)
    .replace(/[\r\n\t\u2028\u2029]+/g, ' ')
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

function longestRun(s: string, ch: string): number {
  let best = 0;
  let run = 0;
  for (const c of s) {
    run = c === ch ? run + 1 : 0;
    if (run > best) best = run;
  }
  return best;
}

/** Email text as a CommonMark code span: a fence longer than any backtick run inside, padded when an edge would be ambiguous. */
export function code(s: string): string {
  const t = oneLine(s);
  if (!t.trim()) return '(empty)';
  const fence = '`'.repeat(longestRun(t, '`') + 1);
  const pad = /^[` ]|[` ]$/.test(t) ? ' ' : '';
  return `${fence}${pad}${t}${pad}${fence}`;
}

/** Our own sentences, which can quote a domain from the email: Markdown syntax characters are escaped. */
function prose(s: string): string {
  return oneLine(s).replace(/[\\`*_[\]<>|~]/g, '\\$&');
}

function addr(a: Address | null): string {
  if (!a) return '';
  return code(a.name ? `${a.name} <${a.address}>` : a.address);
}

function capped<T>(items: T[], line: (item: T, i: number) => string): string[] {
  const out = items.slice(0, MAX_ITEMS).map(line);
  if (items.length > MAX_ITEMS) out.push(`- ${items.length - MAX_ITEMS} more not listed; the JSON report has all of them.`);
  return out;
}

function sections(a: Analysis, level: number): string[] {
  const h = '#'.repeat(Math.min(6, level + 1));
  const out: string[] = [];
  const s = a.summary;

  out.push(`${h} Message`, '');
  const rows: [string, string][] = [
    ['From', addr(s.from)],
    ['Reply-To', s.replyTo.map(addr).join(', ')],
    ['Return-Path', addr(s.returnPath)],
    ['Sender', addr(s.sender)],
    ['To', s.to.map(addr).join(', ')],
    ['Cc', s.cc.map(addr).join(', ')],
    ['Subject', s.subject ? code(s.subject) : ''],
    ['Date', s.date ? code(s.date) : ''],
    ['Message-ID', s.messageId ? code(s.messageId) : ''],
  ];
  for (const [k, v] of rows) if (v) out.push(`- ${k}: ${v}`);
  if (!rows.some(([, v]) => v)) out.push('- No sender, recipient or subject headers.');

  out.push('', `${h} Reasons`, '');
  if (!a.findings.length) out.push('No warning signs were found by any check.');
  for (const f of a.findings) {
    out.push(`- **${SEVERITY_LABEL[f.severity]}${f.points ? `, +${f.points}` : ''}:** ${prose(f.title)}. ${prose(f.explanation)}`);
    out.push(...capped(f.evidence, (e) => `  - ${code(e)}`));
  }
  if (a.reassurances.length) {
    out.push('', `${h} Points in its favour`, '', ...a.reassurances.map((r) => `- ${prose(r)}`));
  }

  out.push('', `${h} Authentication`, '');
  const { primary, verified, alignment } = a.auth;
  if (!primary) {
    out.push('No Authentication-Results header was found, so SPF, DKIM and DMARC could not be reviewed.');
  } else {
    out.push(verified
      ? `Checked by ${code(primary.authservId || 'the receiving server')} when the message arrived.`
      : '**Unverified:** these results could not be tied to any receiving server in the delivery path, so anyone could have written them.');
    out.push('');
    for (const r of primary.results) out.push(`- **${prose(r.method.toUpperCase())} ${prose(r.result)}**${r.domain ? ` ${code(r.domain)}` : ''}: ${prose(r.explanation)}`);
    if (alignment.fromDomain) {
      out.push(`- Alignment with the From domain ${code(alignment.fromDomain)}: SPF ${alignment.spfAligned ? 'aligned' : 'not aligned'}, DKIM ${alignment.dkimAligned ? 'aligned' : 'not aligned'}.`);
    }
  }

  out.push('', `${h} Delivery path`, '');
  if (!a.hops.length) out.push('No Received headers, so the delivery path is unknown.');
  out.push(...capped(a.hops, (hop) => {
    const when = [hop.date ? formatUtc(hop.date) : 'no readable date', hop.delaySeconds !== null && formatDelay(hop.delaySeconds)].filter(Boolean).join(', ');
    return `${hop.index}. ${code(hop.from ?? 'unknown')}${hop.fromIp ? ` ${code(hop.fromIp)}` : ''} to ${code(hop.by ?? 'unknown')} (${when})`;
  }));

  out.push('', `${h} Links`, '');
  if (!a.links.length) out.push('No links found.');
  out.push(...capped(a.links, (l) => {
    const notes = [
      l.text !== null && `text ${code(l.text)}`,
      l.unwrappedVia.length > 0 && `unwrapped from ${prose(l.unwrappedVia.join(' → '))}`,
    ].filter(Boolean);
    const issues = [...l.issues, ...l.domainIssues].map((i) => `\n  - ${code(i.detail)}`).join('');
    return `- ${code(defang(l.finalUrl))}${notes.length ? ` (${notes.join('; ')})` : ''}${issues}`;
  }));

  out.push('', `${h} Attachments`, '');
  if (!a.attachments.length) out.push('No attachments.');
  out.push(...capped(a.attachments, (att) => [
    `- ${code(att.filename)}, ${formatBytes(att.size)}, declared ${code(att.contentType)}${att.detectedType ? `, content looks like ${prose(att.detectedType)}` : ''}`,
    `  - SHA-256 ${code(att.sha256)}`,
    ...att.issues.map((i) => `  - ${code(i.detail)}`),
    ...(att.zipEntries.length ? [`  - ${att.zipEntries.length} files inside: ${att.zipEntries.slice(0, 20).map(code).join(', ')}${att.zipEntries.length > 20 ? ', …' : ''}`] : []),
  ].join('\n')));

  const iocs = observables(a);
  if (iocs.length) {
    const shownIocs = iocs.slice(0, MAX_ITEMS).map(oneLine);
    const fence = '`'.repeat(Math.max(3, longestRun(shownIocs.join('\n'), '`') + 1));
    out.push('', `${h} Observables`, '', 'Every sender domain, link and attachment hash, defanged, for lookups in your own tools. Not all of them are malicious.', '', `${fence}text`, ...shownIocs, fence);
    if (iocs.length > MAX_ITEMS) out.push('', `${iocs.length - MAX_ITEMS} more not listed; the JSON report has all of them.`);
  }

  out.push('', `${h} What to do next`, '', ...a.nextSteps.map((step, i) => `${i + 1}. ${prose(step)}`));

  for (const att of a.attachments.slice(0, MAX_ITEMS)) {
    if (att.email) out.push('', `${h} Attached email ${code(att.filename)}`, '', headline(att.email), '', ...sections(att.email, level + 1));
  }
  return out;
}

/** Unique sender domains, link URLs and hosts, and attachment hashes, defanged. */
function observables(a: Analysis): string[] {
  const s = a.summary;
  const domains = [s.from, s.sender, s.returnPath, ...s.replyTo].map((x) => x?.domain).filter((d): d is string => !!d);
  const hosts = a.links.map((l) => l.host).filter((d): d is string => !!d);
  const urls = a.links.map((l) => l.finalUrl).filter((u) => /^https?:/i.test(u));
  const set = new Set([
    ...[...domains, ...hosts].map((d) => d.toLowerCase().replace(/\./g, '[.]')),
    ...urls.map(defang),
    ...a.attachments.map((x) => `sha256:${x.sha256}`),
  ]);
  return [...set];
}

const headline = (a: Analysis) => `**Score ${a.score}/100: ${LEVEL_LABEL[a.level]}.** ${prose(a.verdict)}`;

/** A defanged Markdown report of an analysis, for pasting into a ticket, chat or case notes. */
export function toMarkdown(a: Analysis): string {
  return [
    `# Email report: ${a.summary.subject ? code(a.summary.subject) : '(no subject)'}`,
    '',
    headline(a),
    '',
    'Warning signs, not a verdict: attackers can pass every check, and legitimate mail can trip some.',
    '',
    ...sections(a, 1),
    '',
    '---',
    '',
    `Made offline by ${a.tool.name} ${prose(a.tool.version)}. Links and domains are defanged; text from the email is shown in code spans.`,
    '',
  ].join('\n');
}
