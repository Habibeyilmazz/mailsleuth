import { readable } from './domains';

// Social-engineering phrases. English only for now; each match is shown to the user as the reader would see it.

export type LanguageCategory = 'urgency' | 'credentials' | 'money' | 'threat';

const PATTERNS: Record<LanguageCategory, RegExp[]> = {
  urgency: [
    /\burgent(ly)?\b/i,
    /\bimmediate(ly)?\b/i,
    /\bwithin (the next )?(\d+|twenty[- ]four|forty[- ]eight) ?(hours?|hrs|minutes)\b/i,
    /\bact (now|fast|quickly)\b/i,
    /\b(final|last) (notice|warning|reminder|attempt)\b/i,
    /\bexpires? (today|tonight|soon|in \d+)/i,
    /\bas soon as possible\b|\basap\b/i,
    /\btime[- ]sensitive\b/i,
    /\bkeep (this|it) (between us|confidential|quiet|to yourself)\b/i,
  ],
  credentials: [
    /\b(verify|confirm|validate|update|re-?activate|unlock) (your|the) (account|identity|password|login|credentials|mailbox|e-?mail|details|information)\b/i,
    /\b(sign|log) ?in (now )?to (avoid|restore|keep|prevent|confirm|verify|unlock)\b/i,
    /\bunusual (sign-?in|login|activity)\b/i,
    /\bpassword (expires|has expired|will expire|expiration)\b/i,
    /\bmailbox (is )?(full|almost full|storage)\b|\bstorage (is )?full\b/i,
    /\bre-?enter your password\b/i,
    /\b(account|access) (has been |will be )?(suspended|locked|limited|disabled|restricted|terminated|closed|deactivated)\b/i,
  ],
  money: [
    /\bgift ?cards?\b/i,
    /\bwire transfer\b/i,
    /\b(change|update)[sd]? (of |to |in )?(our |my |the )?(bank|banking|payment) (details|account|information)\b/i,
    /\b(invoice|payment) (is )?(overdue|past due|attached|failed|declined|pending)\b/i,
    /\b(bitcoin|crypto(currency)?|usdt) (payment|wallet|address)\b/i,
    /\b(refund|tax refund|unclaimed|compensation) (is )?(available|pending|approved)\b/i,
  ],
  threat: [
    /\blegal action\b/i,
    /\b(your )?(account|device|computer) (has been|was) (hacked|compromised|infected)\b/i,
    /\b(police|arrest|lawsuit|(to|in) court|court (order|summons|case|hearing|date|appearance))\b/i, // not "tennis court"
  ],
};

export interface LanguageHit {
  category: LanguageCategory;
  phrase: string;
}

export function scanLanguage(raw: string): LanguageHit[] {
  const text = readable(raw); // "ver\u00adify", "vеrify" with a Cyrillic е: filter evasions the reader never sees
  const hits: LanguageHit[] = [];
  const seen = new Set<string>();
  for (const [category, patterns] of Object.entries(PATTERNS) as [LanguageCategory, RegExp[]][]) {
    for (const re of patterns) {
      const m = re.exec(text);
      if (!m) continue;
      const phrase = m[0].toLowerCase();
      if (seen.has(phrase)) continue;
      seen.add(phrase);
      hits.push({ category, phrase: m[0] });
    }
  }
  return hits;
}
