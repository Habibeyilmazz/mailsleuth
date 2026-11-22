// Minimal DOM builder. Email content is hostile input: everything goes through
// textContent / setAttribute, never innerHTML, and bidi controls are shown, not obeyed.
import { revealBidi } from '../core/encoding';

export type Child = Node | string | number | null | undefined | false | Child[];
type Attrs = Record<string, string | number | boolean | null | undefined | ((e: Event) => void)>;

export function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Attrs = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (typeof v === 'function') el.addEventListener(k.replace(/^on/, ''), v as EventListener);
    else if (k === 'class') el.className = String(v);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  append(el, children);
  return el;
}

function append(el: Node, children: Child[]) {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    if (Array.isArray(c)) append(el, c);
    else el.appendChild(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(revealBidi(String(c))) : c);
  }
}

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
