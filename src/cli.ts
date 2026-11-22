import { readFileSync } from 'node:fs';
import { analyze, MAX_INPUT_BYTES, VERSION } from './core/analyze';
import { bytesToBinary } from './core/encoding';

const HELP = `mailsleuth ${VERSION} - explainable suspicious-email analysis, fully offline

Usage:
  mailsleuth [--compact] <message.eml>
  cat message.eml | mailsleuth [--compact] -

Prints the analysis as JSON (score, level, findings with explanations, auth results,
delivery hops, links, attachments with SHA-256). Nothing is sent over the network.

Options:
  --compact   one-line JSON
  --help      show this help
  --version   show the version`;

async function readStdin(): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
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
  let bytes: Uint8Array;
  try {
    bytes = !files.length || files[0] === '-' ? await readStdin() : new Uint8Array(readFileSync(files[0]));
  } catch (e) {
    console.error(`mailsleuth: cannot read ${files[0]}: ${(e as Error).message}`);
    return 2;
  }
  if (bytes.length > MAX_INPUT_BYTES) {
    console.error(`mailsleuth: input is larger than ${MAX_INPUT_BYTES / 1024 / 1024} MB`);
    return 2;
  }
  const result = await analyze(bytesToBinary(bytes));
  process.stdout.write(JSON.stringify(result, null, compact ? 0 : 2) + '\n');
  return 0;
}

main(process.argv.slice(2)).then((code) => {
  process.exitCode = code;
});
