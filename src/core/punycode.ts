// RFC 3492 Punycode decoder (decode only: we show what an xn-- label really says).
// The browser URL API keeps hosts in xn-- form, so we cannot rely on it for this.

const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700, INITIAL_BIAS = 72, INITIAL_N = 128;

function adapt(delta: number, numPoints: number, first: boolean): number {
  delta = first ? Math.floor(delta / DAMP) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > ((BASE - TMIN) * TMAX) >> 1) {
    delta = Math.floor(delta / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW));
}

function digit(c: number): number {
  if (c >= 48 && c <= 57) return c - 22; // 0-9 -> 26-35
  if (c >= 65 && c <= 90) return c - 65;
  if (c >= 97 && c <= 122) return c - 97;
  return BASE;
}

export function decodePunycodeLabel(input: string): string | null {
  // A DNS label is at most 63 octets ("xn--" + 59). Longer input is not a real domain, and decoding
  // 200,000 characters overflowed the String.fromCodePoint(...out) call stack and aborted the analysis.
  if (input.length > 59) return null;
  const out: number[] = [];
  const basic = input.lastIndexOf('-');
  for (let j = 0; j < Math.max(basic, 0); j++) {
    if (input.charCodeAt(j) >= 0x80) return null;
    out.push(input.charCodeAt(j));
  }
  let n = INITIAL_N, bias = INITIAL_BIAS, i = 0;
  for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length; ) {
    const oldi = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (idx >= input.length) return null;
      const d = digit(input.charCodeAt(idx++));
      if (d >= BASE) return null;
      i += d * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (d < t) break;
      w *= BASE - t;
      if (w > 0x7fffffff) return null;
    }
    bias = adapt(i - oldi, out.length + 1, oldi === 0);
    n += Math.floor(i / (out.length + 1));
    i %= out.length + 1;
    if (n > 0x10ffff) return null;
    out.splice(i++, 0, n);
  }
  return String.fromCodePoint(...out);
}

/** "xn--pypal-4ve.example" -> "pаypal.example". Labels that fail to decode are kept as-is. */
export function toUnicodeDomain(domain: string): string {
  return domain
    .split('.')
    .map((label) => (/^xn--/i.test(label) ? decodePunycodeLabel(label.slice(4).toLowerCase()) ?? label : label))
    .join('.');
}
