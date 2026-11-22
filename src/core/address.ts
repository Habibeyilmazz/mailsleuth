import { decodeHeaderValue } from './encoding';

export interface Address {
  name: string;
  address: string;
  domain: string;
}

function splitList(value: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quote = false;
  let angle = 0;
  let paren = 0;
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (c === '\\' && quote) {
      cur += c + (value[++i] ?? '');
      continue;
    }
    if (c === '"' && !paren) quote = !quote;
    else if (!quote) {
      if (c === '<') angle++;
      else if (c === '>') angle = Math.max(0, angle - 1);
      else if (c === '(') paren++;
      else if (c === ')') paren = Math.max(0, paren - 1);
    }
    if (c === ',' && !quote && !angle && !paren) {
      out.push(cur);
      cur = '';
    } else cur += c;
  }
  out.push(cur);
  return out.map((s) => s.trim()).filter(Boolean);
}

/** Parses an address header (From, To, Reply-To...). Group syntax "team: a@x, b@y;" is flattened. */
export function parseAddressList(raw: string | null): Address[] {
  if (!raw) return [];
  // Split before decoding: an encoded display name may contain commas.
  const value = raw.replace(/^[^"<>@,]*:\s*/, '').replace(/;\s*$/, '');
  return splitList(value).map((entry) => {
    const angle = /<([^<>]*)>\s*(?:\([^)]*\))?\s*$/.exec(entry);
    let address: string;
    let name: string;
    if (angle) {
      address = angle[1].trim();
      name = entry.slice(0, angle.index).trim();
    } else {
      const comment = /\(([^)]*)\)/.exec(entry);
      name = comment ? comment[1].trim() : '';
      address = entry.replace(/\([^)]*\)/g, '').trim();
    }
    name = decodeHeaderValue(name.replace(/^"(.*)"$/s, '$1').replace(/\\(.)/g, '$1')).trim();
    address = decodeHeaderValue(address).replace(/^mailto:/i, '');
    const at = address.lastIndexOf('@');
    return { name, address, domain: at > 0 ? address.slice(at + 1).toLowerCase().replace(/\.$/, '') : '' };
  });
}

/** Return-Path is "<addr>" or "<>" (bounces). */
export function parseReturnPath(raw: string | null): Address | null {
  if (!raw) return null;
  const list = parseAddressList(raw);
  return list[0]?.address ? list[0] : null;
}

/** Pulls every email address that appears in free text (e.g. a display name). */
export function findEmailsInText(text: string): string[] {
  return text.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g) ?? [];
}
