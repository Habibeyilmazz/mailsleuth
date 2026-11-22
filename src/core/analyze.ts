import { findEmailsInText, parseAddressList, parseReturnPath, type Address } from './address';
import { inspectAttachment, KIND_LABEL, sniffKind, type AttachmentIssue } from './attachments';
import { buildAuthReport, resultFor, type AuthReport } from './auth';
import { BRANDS, FREE_MAIL } from './data';
import { brandOwning, inspectDomain, normalizeDomain, readable, sameOrg, type DomainIssue } from './domains';
import { binaryToBytes, bytesToBinary, decodeCharset, decodeHeaderValue, decodeHtmlEntities, htmlToText, sha256Hex, textToBinary } from './encoding';
import { scanLanguage, type LanguageHit } from './language';
import { extractUuencoded, getHeader, getHeaders, isAttachment, parseMessage, walkParts, type MimePart } from './mime';
import { isCompoundFile, readMsg, type MsgResult } from './msg';
import { inspectOffice } from './office';
import { inspectPdf } from './pdf';
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
  'multiple-from': ['sender', 'medium', 'The message has more than one sender address', 'A normal email has exactly one From address. With more than one, mail apps and filters can disagree on which is the sender: a known way to show a trusted address while the checks look at another. This report uses the first one.'],
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
  'no-headers': ['sender', 'info', 'No email headers found: only the text and links were checked', 'Sender, authentication and delivery-path checks need the full message source (Gmail: Show original; Outlook: View message source) or the saved .eml file.'],
  'msg-no-headers': ['sender', 'info', 'This Outlook .msg file has no internet headers', 'Outlook keeps the original headers only for mail that arrived from another server. Drafts, sent items, some internal mail and some export tools have none, so SPF/DKIM/DMARC and the delivery path cannot be checked and the sender shown is the one Outlook stored. If you can, get the message forwarded as an attachment from the recipient\'s mailbox, or copy File › Properties › Internet headers in Outlook.'],
  'outlook-msg': ['delivery', 'info', 'Read from an Outlook .msg file', 'Outlook stores the original internet headers, the text and each attachment separately. mailsleuth rebuilt the message from them: the headers are the ones the mail server received, but the MIME layout, and the SHA-256 of an email attached inside it, belong to the rebuilt copy.'],
  'no-auth-results': ['authentication', 'info', 'No authentication results found', 'There is no Authentication-Results header, so SPF/DKIM/DMARC could not be reviewed. Paste the full headers (not just the body) to see them.'],
  'text-mismatch': ['links', 'high', 'Link text shows one site but goes to another', 'The visible text of a link can say anything. Here it names a different site than where the link really leads.'],
  'mailto-mismatch': ['links', 'medium', 'An email link shows one address but writes to another', 'Clicking an email address in a message opens a new email to whatever address the link holds, which need not be the one shown. Used in invoice and CEO fraud to move the conversation to the attacker while you think you are writing to someone you know.'],
  'tracked-link': ['links', 'info', 'Links go through a mailing service\'s click tracking', 'The link text shows the sender\'s own site, but the link goes to their mailing service first, which counts the click and then forwards you. Newsletters do this routinely. The final destination is not visible here, so if a page asks for a password, check its address.'],
  'userinfo': ['links', 'high', 'Link uses the "@" trick', 'In web addresses everything before "@" is a username that browsers ignore, so a trusted name there is pure decoration.'],
  'javascript-uri': ['links', 'high', 'Link runs script code', 'A javascript: or vbscript: link executes code instead of opening a page. Legitimate emails do not need this.'],
  'local-link': ['links', 'medium', 'Link opens a file share or a program, not a web page', 'Links starting with file:, \\\\server\\ or a Windows handler such as search-ms: open a network folder or start a program. Windows can send your login name and password hash to a file share without asking, and fake search windows are used to hand out malware. Some companies link to their own internal shares; mail from outside has no reason to.'],
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
  'pdf-launch': ['attachments', 'high', 'PDF tries to start a program', 'A Launch action asks the PDF reader to open a file or run a program. Ordinary documents do not need one; the reader asks first, and the attack counts on you clicking Allow.'],
  'pdf-javascript': ['attachments', 'medium', 'PDF contains JavaScript', 'Script in a PDF can open web pages, show fake prompts or attack bugs in the reader. Some real forms use it for calculations, so it is a warning sign, not proof.'],
  'pdf-embedded-file': ['attachments', 'medium', 'PDF carries a hidden file', 'A file embedded in the PDF opens from the reader\'s attachments panel and is not checked by most mail filters. It was not inspected here.'],
  'office-remote-content': ['attachments', 'high', 'Office document loads content from the internet when opened', 'The document tells Word, Excel or PowerPoint to fetch a template or object from a web address as soon as it opens. Attackers use this to pull macros or an exploit (for example "Follina", CVE-2022-30190) into a file that looks clean and has no macro of its own.'],
  'pdf-encrypted': ['attachments', 'info', 'Encrypted PDF: its links could not be checked', 'Many ordinary PDFs are encrypted only to stop copying or printing and open without a password, but the encryption also hides their links from this check and from many mail filters. Hover over any link in the PDF before you click it.'],
  'uuencoded': ['attachments', 'low', 'File hidden in the message text (uuencoded)', 'An old way of sending files as lines of text inside the message. Mail apps such as Thunderbird still show it as an attachment, but some mail filters do not look for it, which is why malware senders use it. Today\'s mail apps never send files this way.'],
  'attachment-links': ['attachments', 'info', 'Attachments contain links', 'PDF, HTML and Office attachments can carry links of their own, which mail filters often check less closely than links in the email. "Open the attached document" lures put the real link there. They are listed under Links with the same checks as the email\'s own links.'],
  'onenote': ['attachments', 'medium', 'OneNote attachment', 'OneNote files have been used to hide malicious programs behind fake buttons.'],
  'type-mismatch': ['attachments', 'medium', 'Attachment content does not match its name', 'The file\'s actual content (by its internal structure) is a different type than its extension claims.'],
  'encrypted-archive': ['attachments', 'medium', 'Password-protected archive or document', 'Encryption stops mail scanners from looking inside, which is why attackers send the password in the email body.'],
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
  private seen = new Set<string>(); // id + evidence: evidence.includes() was quadratic over thousands of links
  add(id: string, evidence: string, override?: Partial<Pick<Finding, 'severity'>>) {
    const [category, severity, title, explanation] = CATALOG[id];
    const sev = override?.severity ?? severity;
    const f = this.map.get(id) ?? { id, category, severity: sev, points: POINTS[sev], title, explanation, evidence: [] };
    // A later, more severe instance (e.g. a second attached email) raises the finding.
    if (POINTS[sev] > f.points) [f.severity, f.points] = [sev, POINTS[sev]];
    if (evidence && !this.seen.has(`${id}\0${evidence}`)) {
      this.seen.add(`${id}\0${evidence}`);
      f.evidence.push(evidence);
    }
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
  const shown = readable(from.name);
  const name = shown.toLowerCase();
  // A capital I after a lower-case letter reads as l in most sans-serif fonts: "PaypaI", "AppIe".
  const asL = shown.replace(/(?<=[a-z])I/g, 'l').toLowerCase();

  for (const email of findEmailsInText(name)) {
    if (email.toLowerCase() !== from.address.toLowerCase()) {
      f.add('display-name-address', `name shows ${email}, real address is ${from.address}`);
    }
  }
  for (const brand of BRANDS) {
    const claimed = brand.displayNames.find((n) => {
      const re = new RegExp(`(^|[^a-z0-9])${n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^a-z0-9]|$)`);
      return re.test(name) || re.test(asL);
    });
    if (claimed && fromOwner !== brand) {
      f.add('display-name-brand', `"${from.name}" suggests ${brand.name}, but the address is on ${from.domain}`);
      break;
    }
  }
  if (FREE_MAIL.has(from.domain) && OFFICIAL_NAME.test(name)) {
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
  const perAttachment = new Map<string, number>();
  for (const l of links) {
    const where = l.attachment ? `in ${l.attachment}: ` : '';
    for (const i of l.issues) f.add(i.id, where + i.detail);
    domainFindings(f, l.domainIssues, l.attachment ? `Link in ${l.attachment}` : 'Link');
    if (l.attachment) perAttachment.set(l.attachment, (perAttachment.get(l.attachment) ?? 0) + 1);
  }
  for (const [name, n] of perAttachment) f.add('attachment-links', `${name}: ${n} link${n === 1 ? '' : 's'}`);
}

/** mailto: links are not listed as links, but text showing one address over a link to another is a trick. */
function mailtoChecks(f: Findings, links: { href: string; text: string | null; attachment?: string }[]) {
  const domain = (a: string) => a.slice(a.lastIndexOf('@') + 1);
  for (const l of links) {
    if (!l.text || !/^mailto:/i.test(l.href)) continue;
    const shown = findEmailsInText(l.text);
    const to = l.href.slice(7).split('?')[0];
    let decoded = to;
    try {
      decoded = decodeURIComponent(to);
    } catch {} // a stray % keeps the raw text
    const other = shown.length ? findEmailsInText(decoded).find((t) => !shown.some((s) => sameOrg(domain(s), domain(t)))) : undefined;
    if (other) f.add('mailto-mismatch', `${l.attachment ? `in ${l.attachment}: ` : ''}link text shows ${shown[0]} but writes to ${other}`);
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
  if (attachments.some((a) => a.issues.some((i) => i.id !== 'pdf-encrypted'))) {
    steps.push('Do not open the attachment. If you already did, disconnect the device from the network and tell your IT or security team right away.');
  }
  if (any('language-money', 'reply-to-mismatch', 'mailto-mismatch', 'freemail-official')) {
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

function reassurances(auth: AuthReport, links: LinkInfo[], attachments: AttachmentInfo[], unextracted = 0): string[] {
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
  if (!attachments.length && !unextracted) out.push('The email has no attachments.');
  return out;
}

const MAX_NESTING = 3;
/** Outlook .msg input becomes MIME; other Office compound files (.doc, .xls) are refused. */
function fromMsg(binary: string): MsgResult {
  let msg: MsgResult | null;
  try {
    msg = readMsg(binaryToBytes(binary));
  } catch (e) {
    throw new Error(`this Outlook .msg file is damaged or cut short (${(e as Error).message}). Try saving it from Outlook again.`);
  }
  if (!msg) throw new Error('this is a Microsoft Office file such as .doc or .xls, not an email. Use the .eml or Outlook .msg file of the message.');
  return msg;
}

export async function analyze(binary: string, depth = 0): Promise<Analysis> {
  binary = binary.replace(/^\xEF\xBB\xBF/, ''); // a UTF-8 byte order mark would become part of the first header's name
  // Source pasted into Notepad and saved as "Unicode" is UTF-16; read byte by byte it has no headers at all.
  const utf16 = binary.startsWith('\xFF\xFE') ? 'utf-16le' : binary.startsWith('\xFE\xFF') ? 'utf-16be' : null;
  if (utf16) binary = textToBinary(new TextDecoder(utf16).decode(binaryToBytes(binary)));
  if (/^[\s\0]*$/.test(binary)) throw new Error('it contains no text, so there is nothing to analyze. Check the file was saved or downloaded completely.');
  const msg = isCompoundFile(binary) ? fromMsg(binary) : null;
  // A dropped attachment (invoice.pdf) would otherwise be called "low risk". HTML and RTF can be email text;
  // "MZ" is only taken as a program when binary bytes follow, so a pasted "MZ Bank: …" is still read.
  const kind = msg ? null : sniffKind(binaryToBytes(binary.slice(0, 0x8010)));
  if (kind && kind !== 'html' && kind !== 'rtf' && (kind !== 'exe' || binary.slice(0, 1024).includes('\0'))) {
    throw new Error(`this looks like a ${KIND_LABEL[kind]}, not an email. To check an attachment, analyze the email it came in (.eml or .msg): that also gives its SHA-256 for a VirusTotal lookup.`);
  }
  // A lone CR on the first line means CR-only (old Mac) or "\r\r\n" (CRLF re-saved in text mode) line endings.
  // Normalized only then: a stray CR inside a well-formed message's attachment keeps its bytes and hash.
  // (?<!\r) keeps a long run of CRs linear: a match can only start at the run's first CR.
  if (!msg && /^[^\n]*\r(?!\n)/.test(binary)) binary = binary.replace(/(?<!\r)\r+\n/g, '\n').replace(/\r/g, '\n');
  const root = parseMessage(msg ? msg.mime : binary);
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
  type RawLink = { href: string; text: string | null; source: LinkInfo['source']; attachment?: string };
  const rawLinks: RawLink[] = [];
  const attachmentLinks: RawLink[] = []; // listed after the email's own links, so a link in both keeps its body entry
  const attachments: AttachmentInfo[] = [];
  const structure: Analysis['structure'] = [];
  const depthOf = new Map<MimePart, number>([[root, 0]]);
  const parts = [...walkParts(root)]; // uuencoded files found in a text part are appended as attachments
  const uuNames: string[] = [];
  for (const part of parts) {
    const partDepth = depthOf.get(part) ?? 0;
    part.children.forEach((c) => depthOf.set(c, partDepth + 1));
    structure.push({ depth: partDepth, contentType: part.contentType, filename: part.filename, size: part.body.length });
    if (part.children.length) continue;
    if (isAttachment(part)) {
      // Some mail apps and ticket systems attach a forwarded .eml as application/octet-stream.
      const isEmail = part.contentType === 'message/rfc822' || /\.eml\s*$/i.test(part.filename ?? '');
      const filename = part.filename ?? (isEmail ? 'attached-message.eml' : 'unnamed-attachment');
      // An attached Outlook .msg (common in user reports) is analyzed like an attached .eml; other Office files are not emails.
      const nested = depth < MAX_NESTING && (isEmail || isCompoundFile(bytesToBinary(part.body.subarray(0, 8))));
      const inspected = inspectAttachment(filename, part.body);
      if (inspected.kind === 'pdf') {
        const pdf = await inspectPdf(part.body);
        inspected.issues.push(...pdf.issues);
        for (const href of pdf.uris) attachmentLinks.push({ href, text: null, source: 'pdf', attachment: filename });
      } else if (inspected.kind === 'ooxml') {
        const office = await inspectOffice(part.body);
        inspected.issues.push(...office.issues);
        for (const href of office.uris) attachmentLinks.push({ href, text: null, source: 'office', attachment: filename });
      } else if (inspected.issues.some((i) => i.id === 'html-attachment')) {
        const html = decodeCharset(part.body, part.params['charset']);
        for (const l of extractHtmlLinks(html)) attachmentLinks.push({ ...l, source: 'html', attachment: filename });
        // Bare URLs anywhere in the file: script redirects and <meta> refreshes in HTML phishing pages. Not XML namespaces.
        for (const href of extractTextLinks(decodeHtmlEntities(html))) {
          if (!href.startsWith('http://www.w3.org/')) attachmentLinks.push({ href, text: null, source: 'text', attachment: filename });
        }
      }
      attachments.push({
        filename,
        contentType: part.contentType,
        size: part.body.length,
        sha256: await sha256Hex(part.body),
        detectedType: inspected.kind ? KIND_LABEL[inspected.kind] : null,
        zipEntries: inspected.zipEntries,
        issues: inspected.issues,
        email: nested ? await analyze(bytesToBinary(part.body), depth + 1).catch(() => null) : null,
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
      for (const uu of extractUuencoded(bytesToBinary(part.body))) {
        const file: MimePart = { headers: [], contentType: 'application/octet-stream', params: {}, disposition: 'attachment', filename: uu.filename, body: uu.body, children: [] };
        depthOf.set(file, partDepth + 1);
        parts.push(file);
        uuNames.push(uu.filename);
      }
    }
  }

  // One entry per distinct (URL, visible text): the same URL behind "Home" and behind
  // "paypal.com" must both be checked. Bare URLs from the plain-text part only add new URLs.
  const seen = new Map<string, LinkInfo>();
  const allLinks = [...rawLinks, ...attachmentLinks];
  // A bare URL only adds to the <a> links of the same file (the email itself or one attachment).
  const where = (l: RawLink) => `${l.attachment ?? ''}\0${l.href}`;
  const htmlHrefs = new Set(allLinks.filter((l) => l.source === 'html').map(where));
  for (const l of allLinks) {
    const key = `${l.href}\0${l.text ?? ''}`;
    if (isIgnorableHref(l.href) || seen.has(key) || (l.source === 'text' && htmlHrefs.has(where(l)))) continue;
    const info = analyzeLink(l.href, l.text, l.source, from?.domain);
    info.attachment = l.attachment ?? null;
    seen.set(key, info);
  }
  const links = [...seen.values()];
  const bodyText = texts.join('\n\n').trim();
  const language = scanLanguage(`${summary.subject}\n${bodyText}`);

  const f = new Findings();
  const dmarcPass = resultFor(auth, 'dmarc')?.result === 'pass';
  senderChecks(f, summary, dmarcPass);
  const froms = getHeaders(h, 'from').flatMap((v) => parseAddressList(v));
  if (froms.length > 1) f.add('multiple-from', froms.map((a) => a.address).join(', '));
  if (msg) {
    const id = msg.transportHeaders ? 'outlook-msg' : 'msg-no-headers';
    f.add(id, `message text: ${msg.bodies.join(', ') || 'none stored'}`);
    for (const x of msg.notExtracted) f.add(id, `attachment not extracted, check it in Outlook: ${x}`);
  }
  if (!h.length) f.add('no-headers', '');
  else if (msg?.transportHeaders !== false) authChecks(f, auth); // a .msg without headers has nothing to check
  linkChecks(f, links);
  mailtoChecks(f, allLinks);
  attachmentChecks(f, attachments);
  for (const name of uuNames) f.add('uuencoded', name);
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
    reassurances: reassurances(auth, links, attachments, msg?.notExtracted.length ?? 0),
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
