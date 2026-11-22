import { readable } from './domains';
import { bytesToBinary, revealBidi } from './encoding';
import { inflate } from './pdf';

export type AttachmentIssueId =
  | 'rlo-filename'
  | 'double-extension'
  | 'executable'
  | 'disk-image'
  | 'html-attachment'
  | 'office-macro'
  | 'macro-enabled-type'
  | 'type-mismatch'
  | 'encrypted-archive'
  | 'archive-risky-content'
  | 'onenote'
  | 'pdf-launch'
  | 'pdf-javascript'
  | 'pdf-embedded-file'
  | 'pdf-encrypted'
  | 'office-remote-content';

export interface AttachmentIssue {
  id: AttachmentIssueId;
  detail: string;
}

export type FileKind =
  | 'exe' | 'zip' | 'ooxml' | 'ole' | 'pdf' | 'rar' | '7z' | 'gzip' | 'lnk' | 'iso' | 'html' | 'rtf' | 'png' | 'jpeg' | 'gif' | 'onenote';

export const KIND_LABEL: Record<FileKind, string> = {
  exe: 'Windows program (PE)', zip: 'ZIP archive', ooxml: 'Office document (OOXML)', ole: 'legacy Office/OLE file',
  pdf: 'PDF', rar: 'RAR archive', '7z': '7-Zip archive', gzip: 'gzip archive', lnk: 'Windows shortcut (LNK)',
  iso: 'ISO disk image', html: 'HTML/SVG document', rtf: 'RTF document', png: 'PNG image', jpeg: 'JPEG image',
  gif: 'GIF image', onenote: 'OneNote file',
};

const EXECUTABLE = new Set(['exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'hta', 'ps1', 'msi', 'jar', 'lnk', 'cpl', 'reg', 'dll', 'application', 'appref-ms', 'url', 'scf', 'msc', 'chm', 'xll', 'apk', 'msix', 'msixbundle', 'appx', 'appxbundle']);
const DISK_IMAGE = new Set(['iso', 'img', 'vhd', 'vhdx']);
const HTML = new Set(['htm', 'html', 'shtml', 'xhtml', 'svg', 'mht', 'mhtml']);
const MACRO_EXT = new Set(['docm', 'dotm', 'xlsm', 'xltm', 'xlam', 'pptm', 'potm', 'ppam', 'ppsm', 'sldm']);
const DECOY_EXT = /\.(pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|gif|rtf|csv|zip|wav|mp3|mp4)[\s_.]*\.([a-z0-9-]+)[\s.]*$/i;

const EXT_KIND: Record<string, FileKind[]> = {
  pdf: ['pdf'], doc: ['ole'], xls: ['ole'], ppt: ['ole'], msg: ['ole'], rtf: ['rtf'],
  docx: ['ooxml'], xlsx: ['ooxml'], pptx: ['ooxml'], docm: ['ooxml'], xlsm: ['ooxml'], pptm: ['ooxml'],
  zip: ['zip', 'ooxml'], rar: ['rar'], '7z': ['7z'], gz: ['gzip'], tgz: ['gzip'],
  exe: ['exe'], dll: ['exe'], scr: ['exe'], lnk: ['lnk'], iso: ['iso'], one: ['onenote'],
  htm: ['html'], html: ['html'], svg: ['html'], png: ['png'], jpg: ['jpeg'], jpeg: ['jpeg'], gif: ['gif'],
};

function startsWith(b: Uint8Array, sig: number[], offset = 0): boolean {
  return b.length >= offset + sig.length && sig.every((v, i) => b[offset + i] === v);
}

export interface ZipEntry {
  name: string;
  encrypted: boolean;
  /** Where the entry's local header starts, its compression method (0 stored, 8 deflate) and compressed size. */
  offset: number;
  method: number;
  size: number;
}

/**
 * Reads file names from a ZIP central directory (stored uncompressed, so no inflate needed), plus any
 * local file header it does not list: 7-Zip and WinRAR also open cut-off and concatenated archives.
 */
export function readZipEntries(b: Uint8Array): ZipEntry[] {
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const entries: ZipEntry[] = [];
  const decoder = new TextDecoder();
  let eocd = -1;
  for (let i = b.length - 22; i >= Math.max(0, b.length - 22 - 0xffff); i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  const count = eocd < 0 ? 0 : view.getUint16(eocd + 10, true);
  let p = eocd < 0 ? 0 : view.getUint32(eocd + 16, true);
  for (let n = 0; n < count && p + 46 <= b.length; n++) {
    if (view.getUint32(p, true) !== 0x02014b50) break;
    const flags = view.getUint16(p + 8, true);
    const nameLen = view.getUint16(p + 28, true);
    const extraLen = view.getUint16(p + 30, true);
    const commentLen = view.getUint16(p + 32, true);
    entries.push({
      name: decoder.decode(b.subarray(p + 46, p + 46 + nameLen)),
      encrypted: (flags & 1) === 1,
      offset: view.getUint32(p + 42, true),
      method: view.getUint16(p + 10, true),
      size: view.getUint32(p + 20, true),
    });
    p += 46 + nameLen + extraLen + commentLen;
  }
  const listed = new Set(entries.map((e) => e.name));
  const known = new Map(entries.map((e) => [e.offset, e]));
  // Each header's data is skipped, so the headers of a stored ZIP or .docx inside this one are not read as this archive's.
  for (let i = b.indexOf(0x50); i >= 0 && i + 30 <= b.length; ) {
    let next = i + 1;
    const nameLen = view.getUint16(i + 26, true);
    if (view.getUint32(i, true) === 0x04034b50 && nameLen && i + 30 + nameLen <= b.length) {
      const name = decoder.decode(b.subarray(i + 30, i + 30 + nameLen));
      const size = known.get(i)?.size ?? view.getUint32(i + 18, true);
      next = i + 30 + nameLen + view.getUint16(i + 28, true) + size;
      if (!listed.has(name)) {
        listed.add(name);
        entries.push({ name, encrypted: (view.getUint16(i + 6, true) & 1) === 1, offset: i, method: view.getUint16(i + 8, true), size });
      }
    }
    i = b.indexOf(0x50, next);
  }
  return entries;
}

/** An entry's bytes (stored or deflated), at most `budget` of them; null when it cannot be read (encrypted, other methods, bad header). */
export async function zipEntryData(b: Uint8Array, e: ZipEntry, budget: number): Promise<Uint8Array | null> {
  if (e.encrypted || e.offset + 30 > b.length) return null;
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  if (view.getUint32(e.offset, true) !== 0x04034b50) return null;
  const start = e.offset + 30 + view.getUint16(e.offset + 26, true) + view.getUint16(e.offset + 28, true);
  const raw = b.subarray(start, start + e.size);
  return e.method === 0 ? raw.subarray(0, budget) : e.method === 8 ? inflate(raw, budget, 'deflate-raw') : null;
}

export function sniffKind(b: Uint8Array): FileKind | null {
  if (startsWith(b, [0x4d, 0x5a])) return 'exe';
  if (startsWith(b, [0x50, 0x4b, 0x03, 0x04]) || startsWith(b, [0x50, 0x4b, 0x05, 0x06])) {
    return readZipEntries(b).some((e) => e.name === '[Content_Types].xml') ? 'ooxml' : 'zip';
  }
  if (startsWith(b, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return 'ole';
  if (startsWith(b, [0x25, 0x50, 0x44, 0x46, 0x2d])) return 'pdf';
  if (startsWith(b, [0x52, 0x61, 0x72, 0x21])) return 'rar';
  if (startsWith(b, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return '7z';
  if (startsWith(b, [0x1f, 0x8b])) return 'gzip';
  if (startsWith(b, [0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00])) return 'lnk';
  if (startsWith(b, [0x43, 0x44, 0x30, 0x30, 0x31], 0x8001)) return 'iso';
  if (startsWith(b, [0xe4, 0x52, 0x5c, 0x7b, 0x8c, 0xd8, 0xa7, 0x4d])) return 'onenote';
  if (startsWith(b, [0x89, 0x50, 0x4e, 0x47])) return 'png';
  if (startsWith(b, [0xff, 0xd8, 0xff])) return 'jpeg';
  if (startsWith(b, [0x47, 0x49, 0x46, 0x38])) return 'gif';
  const head = bytesToBinary(b.subarray(0, 512)).replace(/^\xef\xbb\xbf/, '').trimStart().toLowerCase();
  if (head.startsWith('{\\rtf')) return 'rtf';
  if (/^(<!doctype html|<html|<svg|<\?xml[^>]*>\s*<svg|<script|<head|<body|<meta|<form)/.test(head)) return 'html';
  return null;
}

/** A stream or storage name as UTF-16LE inside an OLE container. shortcut: byte search, not a full CFB directory walk. */
function oleHas(b: Uint8Array, name: string): boolean {
  return bytesToBinary(b).includes(name.split('').join('\0') + '\0');
}

export function extensionOf(name: string): string {
  // Windows drops trailing dots and spaces when it saves a file, so "setup.exe." lands as setup.exe.
  const m = /\.([a-z0-9-]+)[\s.]*$/i.exec(name);
  return m ? m[1].toLowerCase() : '';
}

/** A file name whose extension runs code, opens in a browser or mounts a disk: flagged when found inside an archive. */
export function isRiskyName(n: string): boolean {
  const e = extensionOf(n);
  return EXECUTABLE.has(e) || DISK_IMAGE.has(e) || HTML.has(e) || e === 'one';
}

export function inspectAttachment(filename: string, bytes: Uint8Array): { kind: FileKind | null; zipEntries: string[]; issues: AttachmentIssue[] } {
  const issues: AttachmentIssue[] = [];
  const kind = sniffKind(bytes);
  const name = filename.normalize('NFC');
  if (/[\u202a-\u202e\u200f\u2066-\u2069]/.test(name)) {
    issues.push({ id: 'rlo-filename', detail: `file name contains invisible text-direction characters, so the extension you see is not the real one (real name: "${revealBidi(name)}")` });
  }
  const ext = extensionOf(name);
  const decoy = DECOY_EXT.exec(readable(name)); // as displayed: "invoice.pdf<U+200B>.exe" reads .pdf.exe
  const dangerous = EXECUTABLE.has(ext) || HTML.has(ext) || DISK_IMAGE.has(ext);
  if (decoy && dangerous) {
    issues.push({ id: 'double-extension', detail: `"${name}" pretends to be a .${decoy[1].toLowerCase()} file but is really .${ext}` });
  }
  // hasOwn: the extension comes from the attacker, and "x.constructor" must not find Object.prototype.constructor.
  const expected = Object.hasOwn(EXT_KIND, ext) ? EXT_KIND[ext] : undefined;
  if (EXECUTABLE.has(ext)) issues.push({ id: 'executable', detail: `.${ext} files run code on your computer when opened` });
  else if ((kind === 'exe' || kind === 'lnk') && !expected) {
    issues.push({ id: 'executable', detail: `the content is a ${KIND_LABEL[kind]} even though the name does not say so` });
  }
  if (DISK_IMAGE.has(ext) || kind === 'iso') issues.push({ id: 'disk-image', detail: 'disk image files are used to smuggle programs past Windows download warnings' });
  if (HTML.has(ext) || kind === 'html') issues.push({ id: 'html-attachment', detail: 'HTML attachments open in your browser and are a common way to show a fake login page without any link to block' });
  if (ext === 'one' || kind === 'onenote') issues.push({ id: 'onenote', detail: 'OneNote files can hide clickable embedded programs behind fake "click to view" buttons' });

  let zipEntries: string[] = [];
  if (kind === 'zip' || kind === 'ooxml') {
    const entries = readZipEntries(bytes);
    zipEntries = entries.map((e) => e.name);
    if (entries.some((e) => /(^|\/)vbaProject\.bin$/i.test(e.name))) {
      issues.push({ id: 'office-macro', detail: 'the document contains a VBA macro project (vbaProject.bin). Macros can run code when you click "Enable content"' });
    }
    if (entries.some((e) => e.encrypted)) {
      issues.push({ id: 'encrypted-archive', detail: 'the archive is password-protected, which also hides its contents from mail scanners' });
    }
    const risky = zipEntries.filter(isRiskyName);
    if (risky.length) issues.push({ id: 'archive-risky-content', detail: `archive contains ${risky.slice(0, 5).join(', ')}` });
  } else if (kind === 'ole' && oleHas(bytes, '_VBA_PROJECT')) {
    // Word ("Macros/VBA") and Excel ("_VBA_PROJECT_CUR/VBA") both hold a "_VBA_PROJECT" stream.
    issues.push({ id: 'office-macro', detail: 'the legacy Office file contains a VBA macro storage. Macros can run code when you click "Enable content"' });
  }
  // Office saves a password-protected .docx/.xlsx/.pptx as an OLE file with an "EncryptedPackage" stream.
  const encryptedOoxml = kind === 'ole' && expected?.[0] === 'ooxml' && oleHas(bytes, 'EncryptedPackage');
  if (encryptedOoxml) {
    issues.push({ id: 'encrypted-archive', detail: 'the Office document is password-protected, which also hides its contents and any macros from mail scanners' });
  }
  if (MACRO_EXT.has(ext) && !issues.some((i) => i.id === 'office-macro')) {
    issues.push({ id: 'macro-enabled-type', detail: `.${ext} is a macro-enabled Office format` });
  }
  if (kind && expected && !expected.includes(kind) && !encryptedOoxml) {
    issues.push({ id: 'type-mismatch', detail: `named .${ext} but its content is a ${KIND_LABEL[kind]}` });
  }
  return { kind, zipEntries, issues };
}
