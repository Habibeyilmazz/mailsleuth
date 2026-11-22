import { readZipEntries, zipEntryData, type AttachmentIssue } from './attachments';
import { decodeHtmlEntities } from './encoding';

// Links and remote content in Word/Excel/PowerPoint (OOXML) attachments. Every external reference in these
// files is declared in a _rels/*.rels part: hyperlinks, and templates or objects Office fetches when the file opens.
// shortcut: the link's visible text in the document body is not read, so a text/link mismatch inside a document is not checked.

const MAX_INFLATED = 32 * 1024 * 1024;
const MAX_PARTS = 500; // real documents have a few dozen .rels parts

export async function inspectOffice(b: Uint8Array): Promise<{ uris: string[]; issues: AttachmentIssue[] }> {
  const uris: string[] = [];
  const remote: string[] = [];
  let budget = MAX_INFLATED;
  const rels = readZipEntries(b).filter((e) => /(^|\/)_rels\/[^/]*\.rels$/i.test(e.name) && !e.encrypted);
  for (const e of rels.slice(0, MAX_PARTS)) {
    if (budget <= 0) break;
    const data = await zipEntryData(b, e, budget);
    if (!data) continue;
    budget -= data.length;
    // [^<>]* stops at the next tag, so a run of unclosed tags stays linear.
    for (const [tag] of new TextDecoder().decode(data).matchAll(/<Relationship\b[^<>]*/gi)) {
      const attr = (n: string) => {
        const m = new RegExp(`\\s${n}\\s*=\\s*(?:"([^"]*)"|'([^']*)')`, 'i').exec(tag);
        return m ? decodeHtmlEntities(m[1] ?? m[2]).trim() : '';
      };
      const target = attr('Target');
      if (attr('TargetMode').toLowerCase() !== 'external' || !target || /^(file:\/*)?[a-z]:[\\/]/i.test(target)) continue; // C:\…: a template on the author's own disk
      uris.push(target);
      const type = attr('Type').split('/').pop() ?? '';
      // A web address Office fetches on open (template injection, CVE-2022-30190 "Follina"); a share is checked as a link.
      const what = type === 'attachedTemplate' ? 'a template' : type === 'oleObject' ? 'an embedded object' : 'content';
      // Host only: the full URL is listed, defanged, under Links.
      const host = /\/\/([^/\\?#!:]+)/.exec(target)?.[1] ?? 'a web address';
      if (type !== 'hyperlink' && /^[a-z][a-z0-9+.-]+:/i.test(target) && !/^file:/i.test(target)) remote.push(`${what} from ${host}`);
    }
  }
  const issues: AttachmentIssue[] = remote.length
    ? [{ id: 'office-remote-content', detail: `the document loads ${[...new Set(remote)].slice(0, 3).join(', ')} when opened (see Links)` }]
    : [];
  return { uris: [...new Set(uris)], issues };
}
