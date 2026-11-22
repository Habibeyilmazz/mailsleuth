import { URL_SHORTENERS } from './data';
import { inspectDomain, normalizeDomain, sameOrg, type DomainIssue } from './domains';
import { decodeHtmlEntities } from './encoding';

export type LinkIssueId =
  | 'text-mismatch'
  | 'shortener'
  | 'ip-host'
  | 'data-uri'
  | 'javascript-uri'
  | 'userinfo'
  | 'open-redirect'
  | 'risky-download';

export interface LinkIssue {
  id: LinkIssueId;
  detail: string;
}

export interface LinkInfo {
  href: string;
  /** Visible link text (HTML) or null for bare URLs in plain text. */
  text: string | null;
  source: 'html' | 'text';
  /** Destination after unwrapping known redirect wrappers (Safe Links, Proofpoint, Google...). */
  finalUrl: string;
  /** Hostname of finalUrl in its xn-- form, or null for data:, javascript: and unparsable links. */
  host: string | null;
  unwrappedVia: string[];
  issues: LinkIssue[];
  domainIssues: DomainIssue[];
}

const RISKY_DOWNLOAD = /\.(exe|scr|msi|bat|cmd|js|jse|vbs|vbe|wsf|hta|ps1|jar|apk|lnk|iso|img|vhdx?|zip|rar|7z|html?|svg|one)$/i;

function tryUrl(s: string): URL | null {
  try {
    return new URL(s);
  } catch {
    return null;
  }
}

/** One unwrap step for known redirect wrappers. Returns null when the URL is not a wrapper. */
export function unwrapOnce(url: URL): { via: string; url: string } | null {
  const host = url.hostname.toLowerCase();
  const q = url.searchParams;
  if (host.endsWith('safelinks.protection.outlook.com') && q.get('url')) return { via: 'Microsoft Safe Links', url: q.get('url')! };
  if (/(^|\.)google\.[a-z.]+$/.test(host) && url.pathname === '/url' && (q.get('q') || q.get('url'))) {
    return { via: 'Google redirect', url: (q.get('q') || q.get('url'))! };
  }
  if (host === 'urldefense.proofpoint.com' && /^\/v2\/url/.test(url.pathname) && q.get('u')) {
    const decoded = q.get('u')!.replace(/_/g, '/').replace(/-([0-9A-F]{2})/g, '%$1');
    try {
      return { via: 'Proofpoint URL Defense', url: decodeURIComponent(decoded) };
    } catch {
      return null;
    }
  }
  if (host === 'urldefense.com' && url.pathname.startsWith('/v3/__')) {
    const inner = /\/v3\/__(.+?)__;/.exec(url.href)?.[1];
    if (inner) return { via: 'Proofpoint URL Defense (some characters may be masked as *)', url: inner };
  }
  if (/^(l|lm)\.facebook\.com$/.test(host) && url.pathname === '/l.php' && q.get('u')) return { via: 'Facebook link shim', url: q.get('u')! };
  return null;
}

function redirectParam(url: URL): string | null {
  for (const [, value] of url.searchParams) {
    if (/^https?:\/\//i.test(value)) {
      const target = tryUrl(value);
      if (target && !sameOrg(target.hostname, url.hostname)) return value;
    }
  }
  return null;
}

/** Hostname-ish token in visible link text, e.g. "www.paypal.com" or "https://paypal.com/login". */
function hostInText(text: string): string | null {
  const m = /^(?:https?:\/\/)?((?:[a-z0-9¡-￿-]+\.)+[a-z¡-￿]{2,})(?:[:/?#]\S*)?$/i.exec(text.trim());
  // Through URL so a Unicode host in the text compares equal to its xn-- form in the href.
  return m ? (tryUrl('http://' + m[1])?.hostname ?? normalizeDomain(m[1])) : null;
}

export function analyzeLink(href: string, text: string | null, source: LinkInfo['source']): LinkInfo {
  const info: LinkInfo = { href, text, source, finalUrl: href, host: null, unwrappedVia: [], issues: [], domainIssues: [] };
  const scheme = /^\s*([a-z][a-z0-9+.-]*):/i.exec(href)?.[1].toLowerCase();
  if (scheme === 'data') {
    info.issues.push({ id: 'data-uri', detail: `link opens content embedded in the email itself (${href.slice(0, 40)}…), a trick to show a fake page without any web address` });
    return info;
  }
  if (scheme === 'javascript') {
    info.issues.push({ id: 'javascript-uri', detail: 'link runs script code instead of opening a web page' });
    return info;
  }
  let url = tryUrl(href);
  if (!url) return info;
  for (let i = 0; i < 5; i++) {
    const step = unwrapOnce(url);
    const next = step && tryUrl(step.url);
    if (!step || !next) break;
    info.unwrappedVia.push(step.via);
    url = next;
  }
  info.finalUrl = url.href;
  if (!/^https?:$/.test(url.protocol)) return info;
  const host = url.hostname.toLowerCase();
  info.host = host;

  if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.startsWith('[')) {
    const authority = /^[a-z]+:\/\/(?:[^@/]*@)?([^/:?#]+)/i.exec(href)?.[1] ?? '';
    const obfuscated = info.unwrappedVia.length === 0 && authority.toLowerCase() !== host;
    info.issues.push({
      id: 'ip-host',
      detail: obfuscated
        ? `link uses a disguised numeric address "${authority}" that browsers read as ${host}`
        : `link goes to a bare IP address (${host}) instead of a named website`,
    });
  }
  if (url.username) {
    info.issues.push({ id: 'userinfo', detail: `the part before "@" ("${decodeURIComponent(url.username)}") is ignored by browsers; the real destination is ${host}` });
  }
  if (URL_SHORTENERS.has(host.replace(/^www\./, ''))) {
    info.issues.push({ id: 'shortener', detail: `${host} is a link shortener: the real destination is hidden until you click` });
  }
  const redirect = redirectParam(url);
  if (redirect) info.issues.push({ id: 'open-redirect', detail: `${host} forwards to another site given in the link: ${redirect}` });
  if (RISKY_DOWNLOAD.test(url.pathname)) {
    info.issues.push({ id: 'risky-download', detail: `link points directly at a file (${url.pathname.split('/').pop()}) of a type often used to deliver malware` });
  }
  const shown = text ? hostInText(text) : null;
  if (shown && !sameOrg(shown, host) && !URL_SHORTENERS.has(shown)) {
    info.issues.push({ id: 'text-mismatch', detail: `link text shows ${shown} but it actually goes to ${host}` });
  }
  info.domainIssues = inspectDomain(host);
  return info;
}

/**
 * Pulls links out of HTML. shortcut: regex over <a>/<area>/<form>, which covers what mail
 * clients render as clickable; a real DOM parser would also catch malformed markup.
 */
export function extractHtmlLinks(html: string): { href: string; text: string }[] {
  const out: { href: string; text: string }[] = [];
  const attr = (tag: string, name: string) =>
    new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(tag);
  for (const m of html.matchAll(/<a\b([^>]*)>([\s\S]*?)<\/a\s*>/gi)) {
    const h = attr(m[1], 'href');
    if (h) out.push({ href: decodeHtmlEntities(h[1] ?? h[2] ?? h[3]).trim(), text: decodeHtmlEntities(m[2].replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim() });
  }
  for (const m of html.matchAll(/<(area|form)\b([^>]*)>/gi)) {
    const h = attr(m[2], m[1].toLowerCase() === 'form' ? 'action' : 'href');
    if (h) out.push({ href: decodeHtmlEntities(h[1] ?? h[2] ?? h[3]).trim(), text: m[1].toLowerCase() === 'form' ? '(form submit)' : '' });
  }
  return out;
}

export function extractTextLinks(text: string): string[] {
  return (text.match(/\b(?:https?:\/\/|www\.)[^\s<>"'\])]+/gi) ?? []).map((u) => {
    const clean = u.replace(/[.,;:!?]+$/, '');
    return /^www\./i.test(clean) ? 'http://' + clean : clean;
  });
}

export function isIgnorableHref(href: string): boolean {
  return !href || /^(#|mailto:|tel:|cid:|sms:)/i.test(href) || !/^[a-z][a-z0-9+.-]*:/i.test(href);
}
