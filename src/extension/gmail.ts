// Everything that depends on how Gmail builds its page lives in this file. When Gmail changes and the
// button disappears or the download fails, this is the file to fix.
//
// Hooks used (the same ones Gmail.js relies on, see api.new.get.email_id and email_source_pre in
// https://github.com/KartikTalwar/gmail.js): every message open in a conversation is an element with
//   data-message-id="#msg-f:1790000000000000001"   (msg-a:r-… for mail you sent)
//   data-legacy-message-id="18d6f5c2a4b3e001"      (older hex id, used as a fallback)
// and Gmail's own "Download message" link returns the raw RFC 822 source at
//   <origin><path>?view=att&permmsgid=msg-f:…&attid=0&disp=comp&safe=1&zw   (legacy: th=<hex id>)
// No class names are used: Gmail's are generated and change often; these data attributes have been stable for years.

export const MESSAGE_SELECTOR = '[data-message-id], [data-legacy-message-id]';

/** The query naming this message in Gmail's download URL, or null if the element carries no well-formed id. */
export function messageQuery(el: Element): string | null {
  // Validated strictly: the id is pasted into a URL, so it must not be able to add parameters.
  const id = el.getAttribute('data-message-id')?.replace(/^#/, '');
  if (id && /^msg-[a-z]:[A-Za-z0-9-]{1,40}$/.test(id)) return `permmsgid=${id}`;
  const legacy = el.getAttribute('data-legacy-message-id');
  if (legacy && /^[0-9a-f]{1,16}$/.test(legacy)) return `th=${legacy}`;
  return null;
}

/**
 * Where the "Check" chip goes: at the end of the sender line (the <h3> holding the sender's span[email], the
 * hook Gmail.js uses for the sender), next to Gmail's own "Unsubscribe" link. Without one, first thing in the message.
 */
export function placeBar(message: Element, bar: HTMLElement) {
  const sender = message.querySelector('h3 span[email]')?.closest('h3');
  if (sender) return void sender.append(bar);
  // Gmail lays a message out as a row; a prepended child would otherwise stretch into a full-height column.
  bar.style.alignSelf = 'flex-start';
  message.prepend(bar);
}

/** Gmail's "Download message" URL for the account shown in this tab (/mail/u/0/, /mail/u/1/, …). */
export function rawMessageUrl(loc: { origin: string; pathname: string }, query: string): string {
  const path = /^\/mail\/(u\/\d+\/)?$/.test(loc.pathname) ? loc.pathname : '/mail/u/0/';
  return `${loc.origin}${path}?view=att&${query}&attid=0&disp=comp&safe=1&zw`;
}

/** Gmail answers the download link with a 302 to its attachment host; the body may come only from these two. */
export const GMAIL_HOSTS = ['mail.google.com', 'mail-attachment.googleusercontent.com'];

/**
 * Downloads the raw message with the tab's own Gmail session. Gmail cookies go only to mail.google.com
 * (credentials 'same-origin'); the redirect target is authorized by the signed URL Gmail gives it.
 */
export async function fetchRawMessage(url: string, fetchFn: typeof fetch = fetch): Promise<ArrayBuffer> {
  // A changing parameter, as Gmail.js does: repeating the exact URL can make the redirect bounce back and fail.
  const res = await fetchFn(`${url}&ms=${Date.now()}`, { mode: 'cors', credentials: 'same-origin', cache: 'no-store' });
  if (res.url && !GMAIL_HOSTS.includes(new URL(res.url).hostname)) throw new Error('Gmail redirected the download somewhere unexpected; nothing was read.');
  if (!res.ok) throw new Error(`Gmail answered ${res.status} instead of sending the message. Reload Gmail and try again.`);
  const buf = await res.arrayBuffer();
  const head = new TextDecoder().decode(buf.slice(0, 512)).trimStart().toLowerCase();
  if (!head) throw new Error('Gmail sent an empty message.');
  // Signed out or a changed URL: Gmail answers with a web page, which must not be rated as if it were the email.
  if (head.startsWith('<!doctype html') || head.startsWith('<html')) {
    throw new Error('Gmail sent a web page instead of the message (signed out, or Gmail changed its download link). Reload Gmail and try again.');
  }
  return buf;
}
