import { findEmailsInText, parseAddressList, parseReturnPath, type Address } from './address';
import { inspectAttachment, KIND_LABEL, type AttachmentIssue } from './attachments';
import { buildAuthReport, resultFor, type AuthReport } from './auth';
import { BRANDS, FREE_MAIL } from './data';
import { brandOwning, inspectDomain, normalizeDomain, sameOrg, type DomainIssue } from './domains';
import { bytesToBinary, decodeCharset, decodeHeaderValue, htmlToText, sha256Hex } from './encoding';
import { scanLanguage, type LanguageHit } from './language';
import { getHeader, getHeaders, isAttachment, parseMessage, walkParts, type MimePart } from './mime';
import { buildHops, type Hop } from './received';
import { analyzeLink, extractHtmlLinks, extractTextLinks, isIgnorableHref, type LinkInfo } from './urls';

export type Severity = 'info' | 'low' | 'medium' | 'high';
export type Category = 'sender' | 'authentication' | 'links' | 'attachments' | 'language' | 'delivery';

export interface Finding {
  id: string;
  category: Category;
  severity: Severity;
  points: number;
  title: string;
  explanation: string;
  evidence: string[];
}

export interface AttachmentInfo {
  filename: string;
  contentType: string;
  size: number;
  sha256: string;
  detectedType: string | null;
  zipEntries: string[];
  issues: AttachmentIssue[];
  /** For message/rfc822 attachments (e.g. a user forwarding phishing "as attachment"): its own full analysis. */
  email: Analysis | null;
}

export interface Analysis {
  tool: { name: 'mailsleuth'; version: string };
  summary: {
    subject: string;
    date: string | null;
    messageId: string | null;
    from: Address | null;
    sender: Address | null;
    replyTo: Address[];
    returnPath: Address | null;
    to: Address[];
    cc: Address[];
  };
  score: number;
  level: 'low' | 'suspicious' | 'high';
  verdict: string;
  findings: Finding[];
  reassurances: string[];
  nextSteps: string[];
  auth: AuthReport;
  hops: Hop[];
  links: LinkInfo[];
  attachments: AttachmentInfo[];
  language: LanguageHit[];
  structure: { depth: number; contentType: string; filename: string | null; size: number }[];
  headers: { name: string; value: string }[];
  bodyText: string;
}

export const VERSION = '0.1.0';
/** Larger than any normal email; protects the tab/process from accidental huge drops. */
export const MAX_INPUT_BYTES = 50 * 1024 * 1024;
const POINTS: Record<Severity, number> = { info: 0, low: 5, medium: 12, high: 25 };

const CATALOG: Record<string, [Category, Severity, string, string]> = {
  'display-name-address': ['sender', 'high', 'The sender name shows a different email address', 'Mail apps often show only the display name. Putting a trusted-looking address in the name hides the real sender.'],
  'display-name-brand': ['sender', 'high', 'The sender name claims a brand the address does not belong to', 'Anyone can type any name into the "From" name. What counts is the domain after the @, and here it is not the brand\'s.'],
  'reply-to-mismatch': ['sender', 'medium', 'Replies would go to a different domain', 'If you hit Reply, your answer goes somewhere other than the address shown as the sender. Common in invoice and CEO fraud.'],
  'return-path-mismatch': ['sender', 'low', 'Bounce address (Return-Path) is on a different domain', 'The hidden envelope sender differs from the visible From domain. Newsletters and ticketing systems do this legitimately; it matters more when authentication also fails.'],
  'freemail-official': ['sender', 'low', 'Official-sounding name on a free webmail account', 'Companies, banks and IT departments do not usually write from free webmail addresses.'],
  'lookalike-domain': ['sender', 'high', 'Look-alike domain imitating a known brand', 'The domain is spelled to resemble a well-known brand at a glance (swapped letters, digits for letters, or characters from other alphabets).'],
  'brand-in-domain': ['sender', 'medium', 'Brand name used inside someone else\'s domain', 'A brand name in a subdomain or next to other words (paypal-security.example) does not make it the brand\'s site; only the last part before the extension decides who owns it.'],
  'idn-domain': ['sender', 'medium', 'Internationalized (punycode) domain', 'The domain contains non-Latin characters (shown as xn-- in raw form). Legitimate for many languages, but also used to mimic Latin brand names.'],
  'abused-tld': ['sender', 'low', 'Domain ending often seen in abuse', 'Some cheap or new domain endings are heavily over-represented in phishing. Many sites there are legitimate; it is a weak signal on its own.'],
  'dmarc-fail': ['authentication', 'high', 'The From domain failed DMARC', 'DMARC is the check that ties the visible From address to the real sending systems. Failing it means the From address cannot be trusted.'],
  'spf-fail': ['authentication', 'medium', 'SPF failed: the sending server is not authorized', 'The domain owner publishes which servers may send its mail, and this server is not one of them.'],
  'spf-softfail': ['authentication', 'low', 'SPF soft-failed', 'The sending server is not on the domain\'s list of allowed senders, but the owner only asked for mild suspicion.'],
  'dkim-fail': ['authentication', 'medium', 'DKIM signature failed', 'The message was changed after being signed, or the signature is fake.'],
  'compauth-fail': ['authentication', 'medium', 'Microsoft could not confirm the sender', 'Microsoft 365 combined its checks and concluded the From address is not verified.'],
  'not-aligned': ['authentication', 'low', 'No passing check matches the From domain', 'Some checks may have passed, but for a different domain than the one in the From address, so nothing confirms the visible sender.'],
  'dmarc-none': ['authentication', 'low', 'The From domain has no DMARC protection', 'Without DMARC, anyone can send mail that looks like it comes from this domain and receivers have no policy to block it.'],
  'arc-fail': ['authentication', 'low', 'Broken forwarding chain (ARC)', 'An intermediary\'s record of earlier checks does not validate.'],
  'auth-unverified': ['authentication', 'info', 'Authentication results cannot be tied to a receiving server', 'The pass/fail results below were not written by a server that appears in the delivery path, so anyone could have typed them. Passing results are not counted in the email\'s favour.'],
  'no-auth-results': ['authentication', 'info', 'No authentication results found', 'There is no Authentication-Results header, so SPF/DKIM/DMARC could not be reviewed. Paste the full headers (not just the body) to see them.'],
  'text-mismatch': ['links', 'high', 'Link text shows one site but goes to another', 'The visible text of a link can say anything. Here it names a different site than where the link really leads.'],
  'userinfo': ['links', 'high', 'Link uses the "@" trick', 'In web addresses everything before "@" is a username that browsers ignore, so a trusted name there is pure decoration.'],
  'javascript-uri': ['links', 'high', 'Link runs script code', 'A javascript: link executes code instead of opening a page. Legitimate emails do not need this.'],
  'data-uri': ['links', 'high', 'Link opens a page embedded in the email', 'A data: link carries a whole web page inside the link itself, often a fake login form that no URL filter can see.'],
  'ip-host': ['links', 'medium', 'Link goes to a numeric IP address', 'Real companies link to named websites. Bare or disguised IP addresses avoid domain reputation checks.'],
  'risky-download': ['links', 'medium', 'Link downloads a risky file type', 'The link points straight at a program, archive, disk image or HTML file.'],
  'shortener': ['links', 'low', 'Link shortener hides the destination', 'Shortened links are normal on social media but in email they hide where you will end up.'],
  'open-redirect': ['links', 'low', 'Link forwards to a different site', 'The link goes through one site that bounces you to another one written into the link. Attackers use trusted sites as a springboard.'],
  'rlo-filename': ['attachments', 'high', 'Attachment name uses hidden text-direction characters', 'Invisible Unicode characters reverse part of the name so a program can look like a document.'],
  'double-extension': ['attachments', 'high', 'Attachment hides its real type behind a double extension', 'Windows hides known extensions by default, so "invoice.pdf.exe" shows as "invoice.pdf".'],
  'executable': ['attachments', 'high', 'Attachment is a program or script', 'Opening it runs code on your computer. Legitimate senders almost never email programs.'],
  'disk-image': ['attachments', 'high', 'Attachment is a disk image', 'ISO/IMG/VHD files open like a folder and are used to sneak programs past security warnings.'],
  'office-macro': ['attachments', 'high', 'Office document contains macros', 'Macros are small programs inside the document. "Enable content" lets them run.'],
  'archive-risky-content': ['attachments', 'high', 'Archive contains risky files', 'The attached archive holds programs, scripts, disk images or HTML files.'],
  'html-attachment': ['attachments', 'medium', 'HTML attachment', 'HTML files open in your browser and can show a convincing login page that sends your password elsewhere.'],
  'onenote': ['attachments', 'medium', 'OneNote attachment', 'OneNote files have been used to hide malicious programs behind fake buttons.'],
  'type-mismatch': ['attachments', 'medium', 'Attachment content does not match its name', 'The file\'s actual content (by its internal structure) is a different type than its extension claims.'],
  'encrypted-archive': ['attachments', 'medium', 'Password-protected archive', 'Encryption stops mail scanners from looking inside, which is why attackers send the password in the email body.'],
  'macro-enabled-type': ['attachments', 'medium', 'Macro-enabled Office file type', 'This file format exists specifically to carry macros.'],
  'attached-email': ['attachments', 'medium', 'Contains a forwarded email that looks risky', 'This message carries another email as an attachment, as when someone reports phishing by forwarding it. That inner email has its own analysis below.'],
  'language-credentials': ['language', 'medium', 'Asks you to sign in or confirm account details', 'Requests to "verify your account" or warnings of suspension are the core of credential phishing.'],
  'language-money': ['language', 'medium', 'Mentions payments, gift cards or bank-detail changes', 'Money requests by email, especially changing bank details or buying gift cards, are a classic fraud pattern.'],
  'language-urgency': ['language', 'low', 'Pressure to act quickly or quietly', 'Urgency and secrecy are used to stop you from thinking twice or checking with someone.'],
  'language-threat': ['language', 'low', 'Threatening language', 'Threats of legal action, arrest or account loss are a pressure tactic.'],
  'time-travel': ['delivery', 'low', 'Delivery timestamps go backwards', 'A server claims to have received the message before the previous server sent it. Usually a misconfigured clock, sometimes forged Received headers.'],
};

const OFFICIAL_NAME = /\b(support|security|admin(istrator)?|help ?desk|it (dept|department|team|support)|billing|payroll|accounts?|ceo|cfo|director|president|bank|service desk|customer service|team)\b/i;

class Findings {
  private map = new Map<string, Finding>();
  add(id: string, evidence: string, override?: Partial<Pick<Finding, 'severity'>>) {
    const [category, severity, title, explanation] = CATALOG[id];
    const sev = override?.severity ?? severity;
    const f = this.map.get(id) ?? { id, category, severity: sev, points: POINTS[sev], title, explanation, evidence: [] };
    if (evidence && !f.evidence.includes(evidence)) f.evidence.push(evidence);
    this.map.set(id, f);
  }
  has(id: string) {
    return this.map.has(id);
  }
  list(): Finding[] {
    const order: Severity[] = ['high', 'medium', 'low', 'info'];
    return [...this.map.values()].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  }
}

function domainFindings(f: Findings, issues: DomainIssue[], where: string) {
  const ids: Record<DomainIssue['kind'], string> = {
    idn: 'idn-domain',
    homoglyph: 'lookalike-domain',
    lookalike: 'lookalike-domain',
    'brand-in-domain': 'brand-in-domain',
    'abused-tld': 'abused-tld',
  };
  for (const i of issues) f.add(ids[i.kind], `${where}: ${i.detail}`);
}

function senderChecks(f: Findings, s: Analysis['summary'], dmarcPass: boolean) {
  const from = s.from;
  if (!from?.domain) return;
  const fromOwner = brandOwning(from.domain);

  for (const email of findEmailsInText(from.name)) {
    if (email.toLowerCase() !== from.address.toLowerCase()) {
      f.add('display-name-address', `name shows ${email}, real address is ${from.address}`);
    }
  }
  const nameLower = from.name.toLowerCase();
  for (const brand of BRANDS) {
    const claimed = brand.displayNames.find((n) => new RegExp(`(^|[^a-z0-9])${n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^a-z0-9]|$)`).test(nameLower));
    if (claimed && fromOwner !== brand) {
      f.add('display-name-brand', `"${from.name}" suggests ${brand.name}, but the address is on ${from.domain}`);
      break;
    }
  }
  if (FREE_MAIL.has(from.domain) && OFFICIAL_NAME.test(from.name)) {
    f.add('freemail-official', `"${from.name}" writes from a ${from.domain} account`);
  }
  for (const r of s.replyTo) {
    if (r.domain && !sameOrg(r.domain, from.domain)) f.add('reply-to-mismatch', `From: ${from.address} → Reply-To: ${r.address}`);
  }
  if (s.returnPath?.domain && !sameOrg(s.returnPath.domain, from.domain)) {
    f.add('return-path-mismatch', `From: ${from.domain}, Return-Path: ${s.returnPath.domain}${dmarcPass ? ' (DMARC passed, so this is likely a legitimate mailing service)' : ''}`, dmarcPass ? { severity: 'info' } : undefined);
  }
  const checked = new Set<string>();
  const check = (domain: string, where: string) => {
    const d = normalizeDomain(domain);
    if (!d || checked.has(d)) return;
    checked.add(d);
    domainFindings(f, inspectDomain(d), where);
  };
  check(from.domain, 'From');
  for (const r of s.replyTo) check(r.domain, 'Reply-To');
  if (s.returnPath) check(s.returnPath.domain, 'Return-Path');
}

function authChecks(f: Findings, auth: AuthReport) {
  if (!auth.primary) {
    f.add('no-auth-results', auth.receivedSpf ? `Only a Received-SPF header was found: ${auth.receivedSpf.slice(0, 80)}` : '');
    return;
  }
  if (!auth.verified) {
    f.add('auth-unverified', auth.primary.authservId ? `Authentication-Results by "${auth.primary.authservId}", which is not a receiving server in any Received header` : 'no Received headers to tie the results to');
  }
  const where = auth.primary.authservId ? ` (checked by ${auth.primary.authservId})` : '';
  const dmarc = resultFor(auth, 'dmarc');
  const spf = resultFor(auth, 'spf');
  const dkims = auth.primary.results.filter((r) => r.method === 'dkim');
  const compauth = resultFor(auth, 'compauth');
  if (dmarc?.result === 'fail') f.add('dmarc-fail', `dmarc=fail for ${dmarc.domain ?? auth.alignment.fromDomain}${where}`);
  if (dmarc?.result === 'none') f.add('dmarc-none', `dmarc=none for ${dmarc.domain ?? auth.alignment.fromDomain}`);
  if (spf?.result === 'fail') f.add('spf-fail', `spf=fail for ${spf.domain ?? 'unknown domain'}${where}`);
  if (spf?.result === 'softfail') f.add('spf-softfail', `spf=softfail for ${spf.domain ?? 'unknown domain'}${where}`);
  if (dkims.some((d) => d.result === 'fail') && !dkims.some((d) => d.result === 'pass')) {
    f.add('dkim-fail', dkims.filter((d) => d.result === 'fail').map((d) => `dkim=fail for ${d.domain ?? 'unknown domain'}`).join('; '));
  }
  if (compauth && ['fail', 'softfail'].includes(compauth.result)) {
    f.add('compauth-fail', `compauth=${compauth.result}${compauth.props['reason'] ? ` reason=${compauth.props['reason']}` : ''}`);
  }
  if (!dmarc && auth.alignment.fromDomain && !auth.alignment.spfAligned && !auth.alignment.dkimAligned) {
    f.add('not-aligned', `From domain: ${auth.alignment.fromDomain}`);
  }
  if (auth.arcChain === 'fail') f.add('arc-fail', 'ARC-Seal cv=fail');
}

function linkChecks(f: Findings, links: LinkInfo[]) {
  for (const l of links) {
    for (const i of l.issues) f.add(i.id, i.detail);
    domainFindings(f, l.domainIssues, 'Link');
  }
}

function attachmentChecks(f: Findings, atts: AttachmentInfo[]) {
  for (const a of atts) for (const i of a.issues) f.add(i.id, `${a.filename}: ${i.detail}`);
}

function nestedChecks(f: Findings, atts: AttachmentInfo[]) {
  for (const a of atts) {
    if (!a.email || a.email.level === 'low') continue;
    f.add('attached-email', `${a.filename}: scores ${a.email.score}/100 (${a.email.level}) on its own`, a.email.level === 'high' ? { severity: 'high' } : undefined);
  }
}

function languageChecks(f: Findings, hits: LanguageHit[]) {
  for (const h of hits) f.add(`language-${h.category}`, `"${h.phrase}"`);
}

function deliveryChecks(f: Findings, hops: Hop[]) {
  for (const h of hops) {
    if (h.delaySeconds !== null && h.delaySeconds < -300) {
      f.add('time-travel', `hop ${h.index} (${h.by ?? 'unknown'}) is ${Math.round(-h.delaySeconds / 60)} min earlier than hop ${h.index - 1}`);
    }
  }
}

function nextSteps(level: Analysis['level'], f: Findings, attachments: AttachmentInfo[], links: LinkInfo[]): string[] {
  const steps: string[] = [];
  const any = (...ids: string[]) => ids.some((id) => f.has(id));
  steps.push(
    level === 'high'
      ? 'Treat this email as phishing unless you can confirm otherwise. Do not click its links, open its attachments or reply.'
      : level === 'suspicious'
        ? 'Be careful. Before acting on this email, confirm it through a channel you already trust (an app, a known phone number, a colleague).'
        : 'No strong warning signs were found. That is not a guarantee: if it asks for a password, money or quick action, verify it independently anyway.',
  );
  if (links.some((l) => l.issues.length || l.domainIssues.length)) {
    steps.push('If you need to visit the site, type the address you already know into your browser or use the official app instead of the link.');
  }
  if (attachments.some((a) => a.issues.length)) {
    steps.push('Do not open the attachment. If you already did, disconnect the device from the network and tell your IT or security team right away.');
  }
  if (any('language-money', 'reply-to-mismatch', 'freemail-official')) {
    steps.push('Confirm any payment, gift-card purchase or bank-detail change by phone, using a number you already have, not one from this email.');
  }
  if (any('language-credentials', 'display-name-brand', 'lookalike-domain', 'text-mismatch')) {
    steps.push('If you entered a password after clicking a link in this email, change it now on the real website and review recent account activity.');
  }
  if (level !== 'low') {
    steps.push('Report it: use your mail app\'s "Report phishing" button, or forward it as an attachment to your security team.');
  }
  if (attachments.length || links.length) {
    steps.push('Analysts: check the SHA-256 hashes and link domains in your threat-intel tools. The lookup buttons only send that hash or URL, never the email.');
  }
  return steps;
}

function reassurances(auth: AuthReport, links: LinkInfo[], attachments: AttachmentInfo[]): string[] {
  const out: string[] = [];
  const dmarc = resultFor(auth, 'dmarc');
  if (!auth.verified) {
    // Unverifiable results earn no reassurance.
  } else if (dmarc?.result === 'pass') {
    out.push(`DMARC passed for ${dmarc.domain ?? auth.alignment.fromDomain}: the From address really belongs to the systems that sent it.`);
  } else if (auth.alignment.dkimAligned) {
    out.push(`A valid DKIM signature from the From domain (${auth.alignment.fromDomain}) is present.`);
  }
  if (!links.length) out.push('The email contains no links.');
  if (!attachments.length) out.push('The email has no attachments.');
  return out;
}

const MAX_NESTING = 3;

export async function analyze(binary: string, depth = 0): Promise<Analysis> {
  const root = parseMessage(binary);
  const h = root.headers;
  const from = parseAddressList(getHeader(h, 'from'))[0] ?? null;
  const summary: Analysis['summary'] = {
    subject: decodeHeaderValue(getHeader(h, 'subject') ?? ''),
    date: getHeader(h, 'date'),
    messageId: getHeader(h, 'message-id'),
    from,
    sender: parseAddressList(getHeader(h, 'sender'))[0] ?? null,
    replyTo: parseAddressList(getHeader(h, 'reply-to')),
    returnPath: parseReturnPath(getHeader(h, 'return-path')),
    to: parseAddressList(getHeader(h, 'to')),
    cc: parseAddressList(getHeader(h, 'cc')),
  };

  const hops = buildHops(getHeaders(h, 'received'));
  const auth = buildAuthReport({
    authResults: getHeaders(h, 'authentication-results'),
    arcAuthResults: getHeaders(h, 'arc-authentication-results'),
    arcSeals: getHeaders(h, 'arc-seal'),
    receivedSpf: getHeader(h, 'received-spf'),
    fromDomain: from?.domain ?? '',
    receivedBy: hops.flatMap((x) => (x.by ? [x.by] : [])),
  });

  const texts: string[] = [];
  const rawLinks: { href: string; text: string | null; source: LinkInfo['source'] }[] = [];
  const attachments: AttachmentInfo[] = [];
  const structure: Analysis['structure'] = [];
  const depthOf = new Map<MimePart, number>([[root, 0]]);
  for (const part of walkParts(root)) {
    const partDepth = depthOf.get(part) ?? 0;
    part.children.forEach((c) => depthOf.set(c, partDepth + 1));
    structure.push({ depth: partDepth, contentType: part.contentType, filename: part.filename, size: part.body.length });
    if (part.children.length) continue;
    if (isAttachment(part)) {
      const isEmail = part.contentType === 'message/rfc822';
      const filename = part.filename ?? (isEmail ? 'attached-message.eml' : 'unnamed-attachment');
      const inspected = inspectAttachment(filename, part.body);
      attachments.push({
        filename,
        contentType: part.contentType,
        size: part.body.length,
        sha256: await sha256Hex(part.body),
        detectedType: inspected.kind ? KIND_LABEL[inspected.kind] : null,
        zipEntries: inspected.zipEntries,
        issues: inspected.issues,
        email: isEmail && depth < MAX_NESTING ? await analyze(bytesToBinary(part.body), depth + 1) : null,
      });
      continue;
    }
    const text = decodeCharset(part.body, part.params['charset']);
    if (part.contentType === 'text/html') {
      texts.push(htmlToText(text));
      for (const l of extractHtmlLinks(text)) rawLinks.push({ ...l, source: 'html' });
    } else {
      texts.push(text);
      for (const href of extractTextLinks(text)) rawLinks.push({ href, text: null, source: 'text' });
    }
  }

  // One entry per distinct (URL, visible text): the same URL behind "Home" and behind
  // "paypal.com" must both be checked. Bare URLs from the plain-text part only add new URLs.
  const seen = new Map<string, LinkInfo>();
  const htmlHrefs = new Set(rawLinks.filter((l) => l.source === 'html').map((l) => l.href));
  for (const l of rawLinks) {
    const key = `${l.href}\0${l.text ?? ''}`;
    if (isIgnorableHref(l.href) || seen.has(key) || (l.source === 'text' && htmlHrefs.has(l.href))) continue;
    seen.set(key, analyzeLink(l.href, l.text, l.source));
  }
  const links = [...seen.values()];
  const bodyText = texts.join('\n\n').trim();
  const language = scanLanguage(`${summary.subject}\n${bodyText}`);

  const f = new Findings();
  const dmarcPass = resultFor(auth, 'dmarc')?.result === 'pass';
  senderChecks(f, summary, dmarcPass);
  authChecks(f, auth);
  linkChecks(f, links);
  attachmentChecks(f, attachments);
  nestedChecks(f, attachments);
  languageChecks(f, language);
  deliveryChecks(f, hops);

  const findings = f.list();
  const score = Math.min(100, findings.reduce((s, x) => s + x.points, 0));
  const level: Analysis['level'] = score >= 50 ? 'high' : score >= 20 ? 'suspicious' : 'low';
  const verdict =
    level === 'high'
      ? 'Several strong signs of phishing or fraud.'
      : level === 'suspicious'
        ? 'Some warning signs worth checking before you act.'
        : 'No strong warning signs found.';

  return {
    tool: { name: 'mailsleuth', version: VERSION },
    summary,
    score,
    level,
    verdict,
    findings,
    reassurances: reassurances(auth, links, attachments),
    nextSteps: nextSteps(level, f, attachments, links),
    auth,
    hops,
    links,
    attachments,
    language,
    structure,
    headers: h.map((x) => ({ name: x.name, value: decodeHeaderValue(x.raw) })),
    bodyText,
  };
}

/** Raw bytes of a message/rfc822 attachment, for analyzing a forwarded email on its own. */
