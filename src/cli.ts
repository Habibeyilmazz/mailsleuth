import { createReadStream } from 'node:fs';
import { analyze, MAX_INPUT_BYTES, VERSION } from './core/analyze';
import { bytesToBinary, escapeJsonControls } from './core/encoding';

const HELP = `mailsleuth ${VERSION} - explainable suspicious-email analysis, fully offline

Usage:
  mailsleuth [--compact] <message.eml | message.msg>
  cat message.eml | mailsleuth [--compact] -

Prints the analysis as JSON (score, level, findings with explanations, auth results,
delivery hops, links, attachments with SHA-256). Nothing is sent over the network.

Options:
  --compact   one-line JSON
  --help      show this help
  --version   show the version`;

/** Reads at most MAX_INPUT_BYTES, so /dev/zero or an endless pipe cannot exhaust memory; null when larger. */
async function readLimited(stream: NodeJS.ReadableStream): Promise<Uint8Array | null> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of stream) {
    total += (chunk as Buffer).length;
    if (total > MAX_INPUT_BYTES) return null;
    chunks.push(chunk as Buffer);
  }
  return new Uint8Array(Buffer.concat(chunks));
}

async function main(argv: string[]): Promise<number> {
  if (argv.includes('--help') || argv.includes('-h')) {
    console.log(HELP);
    return 0;
  }
  if (argv.includes('--version')) {
    console.log(VERSION);
    return 0;
  }
  const compact = argv.includes('--compact');
  const files = argv.filter((a) => a === '-' || !a.startsWith('-'));
  const unknown = argv.filter((a) => a.startsWith('-') && a !== '-' && a !== '--compact');
  if (unknown.length || files.length > 1 || (!files.length && process.stdin.isTTY)) {
    if (unknown.length) console.error(`Unknown option: ${unknown[0]}\n`);
    console.error(HELP);
    return 2;
  }
  let bytes: Uint8Array | null;
  try {
    bytes = await readLimited(!files.length || files[0] === '-' ? process.stdin : createReadStream(files[0]));
  } catch (e) {
    console.error(`mailsleuth: cannot read ${files[0]}: ${(e as Error).message}`);
    return 2;
  }
  if (!bytes) {
    console.error(`mailsleuth: input is larger than ${MAX_INPUT_BYTES / 1024 / 1024} MB`);
    return 2;
  }
  const binary = bytesToBinary(bytes);
  // An empty file (a failed download or save) would otherwise be reported as "low" risk.
  if (!binary.trim()) {
    console.error(`mailsleuth: ${files[0] && files[0] !== '-' ? files[0] : 'input'} is empty`);
    return 2;
  }
  let result;
  try {
    result = await analyze(binary);
  } catch (e) {
    console.error(`mailsleuth: cannot analyze ${files[0] && files[0] !== '-' ? files[0] : 'input'}: ${(e as Error).message}`);
    return 2;
  }
  process.stdout.write(escapeJsonControls(JSON.stringify(result, null, compact ? 0 : 2)) + '\n');
  return 0;
}

main(process.argv.slice(2)).then((code) => {
  process.exitCode = code;
});
