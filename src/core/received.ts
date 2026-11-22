import { decodeRawHeader } from './encoding';

export interface Hop {
  /** 1 = first server that handled the message (bottom-most Received header). */
  index: number;
  from: string | null;
  fromIp: string | null;
  by: string | null;
  protocol: string | null;
  /** ISO timestamp, or null if the date could not be parsed. */
  date: string | null;
  /** Seconds since the previous hop, null when either date is unknown. Negative = clock skew or forgery. */
  delaySeconds: number | null;
  raw: string;
}

const IP_RE = /\[(?:IPv6:)?([0-9a-fA-F:.]+)\]|\b(\d{1,3}(?:\.\d{1,3}){3})\b/;

const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
// RFC 5322 4.3 zone names, in hours. Other names (CET, IST, military letters) are ambiguous.
const ZONES: Record<string, number> = { ut: 0, utc: 0, gmt: 0, z: 0, edt: -4, est: -5, cdt: -5, cst: -6, mdt: -6, mst: -7, pdt: -7, pst: -8 };
// Single spaces only: the input is whitespace-collapsed first, so nothing here can backtrack over a long run.
const DATE_RE = /^(?:[a-z]+ ?, ?)?(\d{1,2}) ([a-z]{3})[a-z]* (\d{2,4}) (\d{1,2}):(\d{2})(?::(\d{2})(?:\.\d+)?)? ?(?:([+-])(\d{2})(\d{2})|([a-z]+))?/i;

/**
 * RFC 5322 date-time, parsed here rather than by Date.parse, which differs between browsers and reads a date
 * without a zone as the viewer's local time. No zone, an unknown zone name or an impossible date gives null.
 */
export function parseDate(text: string): Date | null {
  // [^()] not [^)]: the latter rescans to the end from every "(" and is quadratic on "((((…".
  const cleaned = text.replace(/\([^()]*\)/g, '').replace(/\s+/g, ' ').trim();
  const m = DATE_RE.exec(cleaned);
  if (!m) return null;
  const [, day, mon, yearText, hour, min, sec = '0', sign, zh, zm, zoneName] = m;
  const month = MONTHS.indexOf(mon.toLowerCase());
  let year = Number(yearText);
  if (yearText.length === 2) year += year < 50 ? 2000 : 1900;
  else if (yearText.length === 3) year += 1900;
  const zone = zoneName?.toLowerCase();
  const offsetMin = sign ? (sign === '-' ? -1 : 1) * (Number(zh) * 60 + Number(zm)) : zone && Object.hasOwn(ZONES, zone) ? ZONES[zone] * 60 : null;
  if (offsetMin === null || month < 0 || year < 1900 || +hour > 23 || +min > 59 || +sec > 60) return null;
  const local = new Date(Date.UTC(year, month, +day, +hour, +min, +sec));
  if (local.getUTCDate() !== +day) return null; // 31 Feb
  return new Date(local.getTime() - offsetMin * 60000);
}

export function parseReceived(raw: string): Omit<Hop, 'index' | 'delaySeconds'> {
  const value = decodeRawHeader(raw);
  const semi = value.lastIndexOf(';');
  const main = semi >= 0 ? value.slice(0, semi) : value;
  const date = semi >= 0 ? parseDate(value.slice(semi + 1)) : null;
  // "from" is always the first clause; anywhere else it is inside a comment, as in
  // Postfix's "by host (Postfix, from userid 0)". by/with are matched outside comments.
  const from = /^\s*from\s+([^\s;()]+)(\s*\([^)]*\))?/i.exec(main);
  const bare = main.replace(/\([^()]*\)/g, ' ');
  const by = /\bby\s+([^\s;()]+)/i.exec(bare);
  const withProto = /\bwith\s+([^\s;()]+)/i.exec(bare);
  // Prefer the IP the receiving server recorded (in the comment after "from").
  const ipSource = from?.[2] ?? main;
  const ip = IP_RE.exec(ipSource) ?? IP_RE.exec(main);
  return {
    from: from?.[1] ?? null,
    fromIp: ip ? (ip[1] ?? ip[2]) : null,
    by: by?.[1] ?? null,
    protocol: withProto?.[1] ?? null,
    date: date ? date.toISOString() : null,
    raw: value,
  };
}

/** Received headers are prepended by each server, so the list is reversed to get delivery order. */
export function buildHops(receivedHeaders: string[]): Hop[] {
  const hops: Hop[] = [];
  [...receivedHeaders].reverse().forEach((raw, i) => {
    const h = parseReceived(raw);
    const prev = hops[i - 1];
    const delaySeconds = prev?.date && h.date ? Math.round((Date.parse(h.date) - Date.parse(prev.date)) / 1000) : null;
    hops.push({ index: i + 1, delaySeconds, ...h });
  });
  return hops;
}

export function isPrivateIp(ip: string): boolean {
  return /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip) || /^(::1$|f[cd]|fe80)/i.test(ip);
}
