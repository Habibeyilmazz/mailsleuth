import { ABUSED_TLDS, BRANDS, MULTI_LABEL_SUFFIXES, type Brand } from './data';
import { toUnicodeDomain } from './punycode';

export function normalizeDomain(domain: string): string {
  return domain.trim().toLowerCase().replace(/\.$/, '');
}

/** Registrable ("organizational") domain: mail.paypal.co.uk -> paypal.co.uk. */
export function orgDomain(domain: string): string {
  const labels = normalizeDomain(domain).split('.');
  if (labels.length <= 2) return labels.join('.');
  const lastTwo = labels.slice(-2).join('.');
  return labels.slice(MULTI_LABEL_SUFFIXES.has(lastTwo) ? -3 : -2).join('.');
}

export function sameOrg(a: string, b: string): boolean {
  return orgDomain(a) === orgDomain(b);
}

export function brandOwning(domain: string): Brand | null {
  const d = normalizeDomain(domain);
  return BRANDS.find((b) => b.domains.some((bd) => d === bd || d.endsWith('.' + bd))) ?? null;
}

// Characters that render (nearly) like Latin letters. Covers the usual Cyrillic/Greek
// suspects plus ASCII digit swaps; not the full Unicode confusables table.
const CONFUSABLE: Record<string, string> = {
  а: 'a', в: 'b', е: 'e', ё: 'e', к: 'k', м: 'm', н: 'h', о: 'o', р: 'p', с: 'c', т: 't', у: 'y', х: 'x',
  і: 'l', ї: 'l', ј: 'j', ѕ: 's', ԁ: 'd', ԛ: 'q', ԝ: 'w', ӏ: 'l', ɡ: 'g', ɑ: 'a', ı: 'l', ł: 'l',
  α: 'a', β: 'b', ε: 'e', η: 'n', ι: 'l', κ: 'k', ν: 'v', ο: 'o', ρ: 'p', τ: 't', υ: 'u', χ: 'x', ω: 'w',
  '0': 'o', '1': 'l', i: 'l', '|': 'l', '!': 'l', '3': 'e', '5': 's', '$': 's', '@': 'a',
};

// Not shown in a mail client's sender line: soft hyphen, zero-width characters and joiners, bidi marks and controls, BOM.
const INVISIBLE = /[\u00ad\u034f\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g;
const NAME_I: Record<string, string> = { і: 'i', ї: 'i', ı: 'i', ι: 'i' }; // look like "i" in a name, unlike in a domain skeleton

/**
 * Text as the reader sees it: invisible characters dropped, full-width letters (NFKC) and Cyrillic/Greek
 * look-alikes folded to Latin. ASCII is left alone, so "Office 365" stays as it is.
 */
export function readable(s: string): string {
  return s
    .normalize('NFKC')
    .replace(INVISIBLE, '')
    .replace(/[^\x00-\x7e]/g, (c) => NAME_I[c.toLowerCase()] ?? CONFUSABLE[c.toLowerCase()] ?? c);
}

export function skeleton(label: string): string {
  return Array.from(label.normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase(), (c) => CONFUSABLE[c] ?? c)
    .join('')
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w');
}

export function levenshtein(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 2) return 3; // callers only care about 0-2
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[b.length];
}

// Brand labels that are also everyday words; matching them would flag half the internet.
const GENERIC_LABELS = new Set(['live', 'office', 'me', 'mac', 'zoom', 'slack', 'wise', 'chase', 'visa', 'booking', 'meta', 'msn', 'x', 'fb', 'wf', 'aws']);

const BRAND_LABELS: { label: string; skel: string; brand: Brand }[] = BRANDS.flatMap((brand) =>
  [...new Set(brand.domains.map((d) => orgDomain(d).split('.')[0]))]
    .filter((label) => label.length >= 3 && !GENERIC_LABELS.has(label))
    .map((label) => ({ label, skel: skeleton(label), brand })),
);

export type DomainIssueKind = 'idn' | 'homoglyph' | 'lookalike' | 'brand-in-domain' | 'abused-tld';

export interface DomainIssue {
  kind: DomainIssueKind;
  domain: string;
  brand?: string;
  detail: string;
}

export function inspectDomain(rawDomain: string): DomainIssue[] {
  const domain = normalizeDomain(rawDomain);
  if (!domain || brandOwning(domain)) return [];
  const issues: DomainIssue[] = [];
  const unicode = toUnicodeDomain(domain);
  const isIdn = /[^\x00-\x7f]/.test(unicode);
  if (isIdn) {
    issues.push({
      kind: 'idn',
      domain,
      detail: unicode === domain ? `contains non-Latin characters: ${domain}` : `${domain} actually reads "${unicode}"`,
    });
  }

  const org = orgDomain(unicode);
  const labels = unicode.split('.').slice(0, -(org.split('.').length - 1) || undefined);
  const tokens = [...new Set(labels.flatMap((l) => [l, ...l.split('-')]).filter(Boolean))];
  const skel = new Map(tokens.map((t) => [t, skeleton(t)])); // once per token, not once per brand
  const seen = new Set<string>();
  for (const { label, skel: labelSkel, brand } of BRAND_LABELS) {
    if (seen.has(brand.name)) continue;
    for (const token of tokens) {
      let kind: DomainIssueKind | null = null;
      if (token === label) kind = 'brand-in-domain';
      else if (skel.get(token) === labelSkel) kind = /[^\x00-\x7f]/.test(token) ? 'homoglyph' : 'lookalike';
      // Same first letter and no short tokens: without this, everyday words like "cloud"
      // (icloud), "finance" (binance) and "strip" (stripe) were flagged as look-alikes.
      else if (label.length >= 6 && token.length >= 6 && token[0] === label[0] && /^[a-z0-9]+$/.test(token) && levenshtein(token, label) === 1) kind = 'lookalike';
      if (!kind) continue;
      seen.add(brand.name);
      const detail =
        kind === 'brand-in-domain'
          ? `${domain} uses the name "${label}" but is not a ${brand.name} domain (${brand.domains[0]})`
          : kind === 'homoglyph'
            ? `${domain}: "${token}" is spelled with look-alike characters to imitate "${label}" (${brand.name})`
            : `${domain}: "${token}" looks very similar to "${label}" (${brand.name})`;
      issues.push({ kind, domain, brand: brand.name, detail });
      break;
    }
  }

  const tld = domain.split('.').pop() ?? '';
  if (ABUSED_TLDS.has(tld)) {
    issues.push({ kind: 'abused-tld', domain, detail: `${domain} ends in .${tld}, a top-level domain that shows up disproportionately in phishing and malware reports` });
  }
  return issues;
}
