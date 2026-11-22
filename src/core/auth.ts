import { sameOrg } from './domains';
import { decodeRawHeader } from './encoding';
import { splitParams } from './mime';

export interface AuthResult {
  method: string;
  result: string;
  props: Record<string, string>;
  comments: string[];
  /** The domain this result is about (SPF envelope domain, DKIM signing domain, DMARC From domain). */
  domain: string | null;
  explanation: string;
  tone: 'good' | 'bad' | 'neutral';
}

export interface AuthHeader {
  header: 'Authentication-Results' | 'ARC-Authentication-Results';
  authservId: string;
  instance: number | null;
  results: AuthResult[];
}

export interface AuthReport {
  /** Topmost Authentication-Results: added by the final receiving system, the only one you can trust. */
  primary: AuthHeader | null;
  /** Lower Authentication-Results headers. Anyone upstream (including the sender) could have written these. */
  earlier: AuthHeader[];
  arc: AuthHeader[];
  /** cv= value from the newest ARC-Seal (pass/fail/none), null when absent. */
  arcChain: string | null;
  receivedSpf: string | null;
  alignment: {
    fromDomain: string;
    spfAligned: boolean;
    dkimAligned: boolean;
  };
}

function domainOf(v: string | undefined): string | null {
  if (!v) return null;
  const d = v.replace(/^"|"$/g, '').split('@').pop()!.toLowerCase().replace(/\.$/, '');
  return d && d !== 'none' ? d : null; // Microsoft writes header.d=none for unsigned mail
}

function explain(method: string, result: string, domain: string | null, comments: string[]): Pick<AuthResult, 'explanation' | 'tone'> {
  const d = domain ?? 'the domain';
  const policy = comments.map((c) => /\bp=(\w+)/i.exec(c)?.[1]).find(Boolean);
  const errors: Record<string, string> = {
    temperror: 'could not be checked because of a temporary DNS problem. It says nothing either way.',
    permerror: `could not be checked because ${d} publishes a broken record. It says nothing either way.`,
  };
  if (errors[result]) return { explanation: `${method.toUpperCase()} ${errors[result]}`, tone: 'neutral' };
  const table: Record<string, Record<string, [string, AuthResult['tone']]>> = {
    spf: {
      pass: [`The server that handed over this message is allowed to send mail for ${d}. Note: ${d} is the hidden envelope (bounce) domain, which can differ from the From address you see.`, 'good'],
      fail: [`The sending server is NOT on ${d}'s list of allowed senders, and ${d} asks receivers to reject such mail.`, 'bad'],
      softfail: [`The sending server is not on ${d}'s list of allowed senders; ${d} only asks receivers to treat such mail with suspicion.`, 'bad'],
      neutral: [`${d} makes no statement about whether this server may send for it.`, 'neutral'],
      none: [`${d} publishes no SPF record, so the sending server could not be checked.`, 'neutral'],
    },
    dkim: {
      pass: [`The message carries a valid digital signature from ${d}, so the signed parts were not changed after ${d} signed them. It proves who signed, not that the signer is honest.`, 'good'],
      fail: [`A digital signature claiming to be from ${d} did not verify. The message was modified after signing, or the signature is forged.`, 'bad'],
      neutral: [`A signature from ${d} was present but could not be evaluated.`, 'neutral'],
      policy: [`A signature from ${d} was present but rejected by the receiver's policy (for example a weak key).`, 'bad'],
      none: ['The message was not digitally signed (no DKIM signature).', 'neutral'],
    },
    dmarc: {
      pass: [`The visible From domain (${d}) passed DMARC: SPF or DKIM passed for a domain that matches it. The message really comes from systems ${d} authorizes. That does not make ${d} itself trustworthy: check it is the domain you expect.`, 'good'],
      fail: [`The visible From domain (${d}) failed DMARC: neither SPF nor DKIM passed for a matching domain. That is a strong sign the From address is forged, although forwarding services sometimes cause it.${policy ? ` ${d}'s published policy is p=${policy.toLowerCase()}.` : ''}`, 'bad'],
      none: [`${d} publishes no DMARC policy, so receivers cannot tell whether mail using its name is genuine.`, 'neutral'],
      bestguesspass: [`${d} has no DMARC record, but the message would have passed if it had one.`, 'neutral'],
    },
    arc: {
      pass: ['The message passed through an intermediary (a mailing list or forwarding service) that recorded the checks it saw, and that record is intact.', 'good'],
      fail: ['The forwarding record (ARC chain) added by intermediaries is broken, so their earlier checks cannot be relied on.', 'bad'],
      none: ['No intermediary recorded a forwarding history (no ARC). Normal for direct mail.', 'neutral'],
    },
    compauth: {
      pass: ["Microsoft's combined authentication verdict is pass.", 'good'],
      fail: ["Microsoft's combined authentication verdict is fail: Microsoft could not confirm the sender is who the From address claims.", 'bad'],
      softfail: ["Microsoft's combined authentication verdict is softfail (weak evidence the sender is genuine).", 'bad'],
      none: ["Microsoft's combined authentication made no verdict.", 'neutral'],
    },
  };
  const hit = table[method]?.[result];
  if (hit) return { explanation: hit[0], tone: hit[1] };
  return { explanation: `${method} check result: ${result}.`, tone: result === 'pass' ? 'good' : result === 'fail' ? 'bad' : 'neutral' };
}

export function parseAuthResults(raw: string, header: AuthHeader['header'] = 'Authentication-Results'): AuthHeader {
  const segments = splitParams(decodeRawHeader(raw));
  let instance: number | null = null;
  if (segments[0] && /^i\s*=\s*\d+$/i.test(segments[0])) instance = Number(segments.shift()!.split('=')[1]);
  const authservId = segments[0] && !/^[\w.-]+\s*=/.test(segments[0]) ? segments.shift()!.replace(/\s+\d+$/, '') : '';
  const results: AuthResult[] = [];
  for (const seg of segments) {
    const comments = [...seg.matchAll(/\(([^)]*)\)/g)].map((m) => m[1]);
    const text = seg.replace(/\([^)]*\)/g, ' ');
    const m = /^\s*([\w.-]+)\s*=\s*([\w-]+)/.exec(text);
    if (!m) continue;
    const method = m[1].toLowerCase();
    const result = m[2].toLowerCase();
    const props: Record<string, string> = {};
    for (const p of text.slice(m[0].length).matchAll(/([\w.-]+)\s*=\s*("[^"]*"|[^\s;]+)/g)) {
      props[p[1].toLowerCase()] = p[2].replace(/^"|"$/g, '');
    }
    const domain =
      method === 'spf' ? domainOf(props['smtp.mailfrom'] ?? props['smtp.helo'])
      : method === 'dkim' ? domainOf(props['header.d'] ?? props['header.i'])
      : method === 'dmarc' ? domainOf(props['header.from'])
      : null;
    results.push({ method, result, props, comments, domain, ...explain(method, result, domain, comments) });
  }
  return { header, authservId, instance, results };
}

export function buildAuthReport(opts: {
  authResults: string[];
  arcAuthResults: string[];
  arcSeals: string[];
  receivedSpf: string | null;
  fromDomain: string;
}): AuthReport {
  const all = opts.authResults.map((r) => parseAuthResults(r));
  const arc = opts.arcAuthResults.map((r) => parseAuthResults(r, 'ARC-Authentication-Results')).sort((a, b) => (b.instance ?? 0) - (a.instance ?? 0));
  const newestSeal = opts.arcSeals
    .map((s) => ({ i: Number(/\bi\s*=\s*(\d+)/.exec(s)?.[1] ?? 0), cv: /\bcv\s*=\s*(\w+)/i.exec(s)?.[1]?.toLowerCase() ?? null }))
    .sort((a, b) => b.i - a.i)[0];
  const primary = all[0] ?? null;
  const fromDomain = opts.fromDomain;
  const pass = (method: string) => (primary?.results ?? []).filter((r) => r.method === method && r.result === 'pass');
  return {
    primary,
    earlier: all.slice(1),
    arc,
    arcChain: newestSeal?.cv ?? null,
    receivedSpf: opts.receivedSpf ? decodeRawHeader(opts.receivedSpf) : null,
    alignment: {
      fromDomain,
      spfAligned: Boolean(fromDomain) && pass('spf').some((r) => r.domain && sameOrg(r.domain, fromDomain)),
      dkimAligned: Boolean(fromDomain) && pass('dkim').some((r) => r.domain && sameOrg(r.domain, fromDomain)),
    },
  };
}

/** First result for a method in the trusted (topmost) header. */
export function resultFor(report: AuthReport, method: string): AuthResult | null {
  return report.primary?.results.find((r) => r.method === method) ?? null;
}
