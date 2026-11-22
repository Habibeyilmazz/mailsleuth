# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added (round 4: feature)
- Outlook `.msg` files, in the web app (drop, pick, or the new sample) and the CLI. Before this, a `.msg` (what Outlook for Windows produces when you drag or save a message) was parsed as text and came out as a near-empty, misleadingly calm report. `src/core/msg.ts` reads the Compound File, the MAPI properties, compressed RTF (LZFu) and HTML encapsulated in RTF, rebuilds the message as MIME, and every existing check runs on it. A `Read from an Outlook .msg file` note says which body was used; a `.msg` without internet headers gets its own note instead of authentication findings.
- `.msg` attachments inside an `.eml`, and messages attached inside a `.msg`, get their own nested analysis like `message/rfc822` attachments (SOC mailboxes often receive user reports this way).
- Sample `samples/07-outlook-sign-request.msg` (synthetic, body only as compressed RTF like most real `.msg` files), written by `scripts/msg.ts` (a small CFB/MSG writer for fixtures).
- `test/msg.test.ts`: the sample end to end, an LZFu vector with back-references from the Python `compressed_rtf` package, HTML de-encapsulation, embedded and attached messages, a `.msg` without headers (a line break in a stored subject cannot forge a header), 8-bit and non-Latin strings, 4096-byte sectors, more than 109 FAT sectors (DIFAT), a looping sector chain, streams sharing sectors, a truncated file, and 300 random corruptions of the sample (each must finish in under 500 ms with a result or a "damaged" error).
- A Codex second-opinion review of `msg.ts` found eight ways a crafted `.msg` could hide content; all fixed before release, each with a test: only the HTML body was checked when RTF also existed (Outlook may show the RTF one), ordinary RTF-only bodies were dropped, OLE-object and cloud-link attachments vanished (and the page then said "no attachments"; they are now named), a `\uN` fallback could swallow the `<` of a link, sector chains ending early and LZFu streams with a bad CRC or no end marker were half-read instead of refused, an unsupported code page threw, and a version 4 stream size over 4 GB was truncated to its low 32 bits. A stored `multipart/*` type on an attachment no longer hides its bytes, and `\fromhtml1` is found after a padded RTF header.
- CLI: a damaged `.msg` or a non-email Office file prints one line and exits 2 instead of a stack trace. CI and `npm run screenshots` check the `.msg` sample and a truncated `.msg`.

### Security
- Denial of service: a 200 KB From/Reply-To header of `(` characters, `<a>(x` runs, or `a.a.a…` in a display name, an Authentication-Results header with 200,000 nested comments, or a Received date full of `(` froze the browser tab or CLI for 15 s to several minutes (quadratic regexes and a peel-one-level-per-pass loop). All are linear now; a 700 KB host name went from 4.5 s to 0.2 s. Timing regression tests in `test/parsing.test.ts` fail on the old code.
- Display spoofing: bidi override/isolate characters in email text were obeyed, so `photo<U+202E>gpj.exe` displayed as `photoexe.jpg` in the attachment list and even in the warning meant to reveal it (`JSON.stringify` does not escape U+202E). The web UI now shows them as `⟨U+202E⟩` markers; CLI output and the copied JSON report escape them and C1 controls as `\uXXXX`. Covered by unit tests, `npm run screenshots` and a CI step.
- Analysis abort: a From domain with a 200,000-character `xn--` label overflowed the call stack in the punycode decoder, so the page showed only an error and the CLI crashed. Labels longer than DNS allows (63 octets) are left undecoded.
- Missed links (baseStriker): relative links under `<base href="https://attacker.example/">` were skipped as relative; they are now resolved against the base, as mail clients that honor `<base>` do.
- Missed host: `href="https://pay&shy;pa1.example"` opens paypa1.example in a browser, but the analyzer kept `&shy;` in the host name and its domain checks saw a name that does not exist.
- Speed: brand skeletons are computed once instead of once per link (80,000 distinct links: 5.0 s to 0.4 s).
- More quadratic paths, found by a Codex second-opinion review of `src/core` and by the new timing fuzz: long `\r` runs in HTML (1 s per 40 KB), long words in Authentication-Results properties, spaces after `<addr>`, a whitespace run in the authserv-id, a punctuation run after a `www.` link, and `evidence.includes()` over thousands of distinct links. The page now also caps evidence lines at 200.
- Comments the RFCs allow no longer hide content: `multipart/mixed (a (b))`, `multipart / mixed`, `boundary=b (x)` (each hid every attachment), `base64 (a (b))` (body left undecoded), `(a"b)` or `(a\()` in Authentication-Results (later results such as `dmarc=fail` were dropped), a comment after the authserv-id (results wrongly unverified), `<a@x> (one) (two)` (domain read as `x>`) and `"a(b)"@x`. One quote- and escape-aware `stripComments` in `mime.ts` handles all of them.
- Missed links: protocol-relative `href="//evil.example/a.exe"` and SVG `xlink:href`.

### Fixed
- CLI read the whole file or pipe before checking the 50 MB limit, so `mailsleuth /dev/zero` exhausted memory; it now stops reading at the limit (CI checks it).
- Web: a hostile email with hundreds of thousands of headers, hops or links built that many DOM rows (500,000 nodes for 1 MB of headers). Each list now shows the first 200 and says how many more the JSON report holds.
- Web: a slow file read could replace a newer analysis, and an unreadable file failed silently; both now handled.
- Web: a very long header name widened the "All headers" table off the page.
- Text box, select and outline-button borders were about 1.3:1 against their backgrounds; now at least 3:1 in both themes.
- Phones: one long unbreakable token (the `data:` link in sample 05) widened the result page past the screen. Grid columns are now `minmax(0, 1fr)` and panels wrap long tokens.
- Desktop: the sticky verdict column was taller than an 860px window, hiding the last "What to do next" steps until the end of the page. It now scrolls on its own and is keyboard-focusable (Shift+Tab from the verdict, then arrow keys/End).
- Dark mode: the logo's magnifier handle was invisible and the lens a white blob; the SVG now has dark colours.
- Input errors ("Nothing to analyze yet", too large, parse failure) were grey text far below the button; they now use the warning colour and empty paste returns focus to the paste box.
- Screen readers: the risk score used `aria-label` on a paragraph, which is not announced; it is now visually hidden text. Copy buttons announce "Copied".
- Pasted body text without headers was silently dropped and scored 0; it is now analyzed (links, wording) with a note that sender and authentication checks need the full source.
- Look-alike false positives: everyday words one edit away from a brand ("cloud", "finance", "strip") and the surname Norton or the word "outlook" in a display name no longer score as brand impersonation.
- Authentication-Results counted as verified when its server matched a forged lower `Received` hop or had no server name; it must now match the newest receiving hop (or a Microsoft 365 hop when unnamed).
- RFC 2045 comments in `Content-Type` / `Content-Transfer-Encoding` hid attachments.
- Link extraction evasions: `href` hidden inside another attribute's value, `>` in quoted attributes, `&colon;` and other named entities, `<span>`-split link text; a new `<a>` now ends the previous one.
- Thousands of unterminated tags made HTML scanning quadratic (30 s for 300 KB); now linear.
- File extensions, entities and auth results named like `Object.prototype` keys (`x.constructor`) crashed or garbled output.
- A second, riskier attached email did not raise the "attached email" severity, so attachment order changed the verdict.
- A lone "<" in HTML text ("price < 5") no longer hides the rest of the message from the wording checks.
- Web UI: a slow earlier analysis can no longer replace the result of a newer one.
- Postfix-style `Received: by host (Postfix, from userid 0)` showed a hop "from userid".
- README brand count (44, not 43); the CLI build no longer copies the web favicon.

### Added
- `npm run fuzz` (`test/fuzz.test.ts`): every syntax fragment, then random mixes, repeated to 60 KB in every header and body position; fails on any analysis over 500 ms or any exception. CI runs it with 3,000 random cases.
- Ctrl+Enter (Cmd+Enter on a Mac) in the paste box analyzes it.
- Touch screens see "Choose an .eml file" instead of "Drop an .eml file here".
- `npm run screenshots` now also checks: no horizontal scroll at 390px on every sample (measured against the device width, since mobile Chrome widens `innerWidth` to fit wide content and hid the old bug), the last next step reachable by keyboard, the empty-paste error, a slow file read racing a sample, and an unreadable file.

### Notes for the next contributor
- Feature round (round 4): `.msg` was the roadmap item a newcomer hits first (Outlook users have no `.eml`). The sample was cross-checked with Python's `olefile` and `extract-msg` (installed only in an ignored `.venv`, not a project dependency): same subject, headers, recovered HTML and attachment SHA-256. No real Outlook-produced `.msg` was available on this machine, so real-world quirks (unusual property layouts, Unicode/ANSI mixes) are untested; `msg.ts` falls back to plain text when no HTML or `\fromhtml` RTF exists. Not extracted: OLE-object and by-reference attachments. The reported gaps from round 3 (Pages never run, Safari/Firefox untested, workflow tag comments unchecked) are unchanged and are not bugs.
- Security round (round 3): after the fixes above, `npm run fuzz` with seeds 1-4 (about 100,000 cases) found nothing over 40 ms. `npm audit`: 0 vulnerabilities. Workflows already had least-privilege permissions, SHA-pinned actions and `persist-credentials: false` (the tag comments next to the SHAs could not be re-checked: this machine could not reach other GitHub repos). History scan found no secrets or real addresses. Codex reviewed `src/core` this round (its first, security-worded prompt was refused by its content filter; a plain code-review prompt worked). Its findings not acted on: unknown `Content-Disposition` values and `Content-Disposition: attachment` on a whole multipart are not treated as attachments (content is still analyzed as body), and CFWS inside property names (`header . from`) is not parsed.
- When adding a regex, run `npm run fuzz`; every bug it found was a `\s*`, `[^)]*` or `+` that can restart from every position of a long run. A lookbehind such as `(?<![\w.-])` or a one-pass loop fixed each.
- An editing tool in this round silently turned `\u202E` escapes into the raw character; write bidi characters in sources as escapes and grep for raw ones before committing.
- Sample 05 imitates Microsoft 365 headers with reserved `example.net` host names, so it now shows "cannot be tied to a receiving server"; that is the new rule working, not a bug.
- Codex reviewed the web UI and CLI in the design round (after a usage-limit wait); its six findings are fixed above. It did not review `src/core` again.
- README screenshots (`docs/screenshots/`) are copied from `test-results/screenshots/` after `npm run screenshots`.

## [0.1.0] - 2026-11-22

### Added
- Offline analysis core (`src/core`, no runtime dependencies) shared by the web app and the CLI: MIME parser, Received-hop timeline, Authentication-Results/ARC explainer, sender and look-alike domain checks, link unwrapping and trick detection, attachment hashing and structure inspection, phrase scan, explainable 0-100 score with next steps.
- Recursive analysis of emails attached as `message/rfc822` (user-reported phishing).
- Browser UI (Vite, vanilla TypeScript) with drop/pick/paste input, six synthetic samples, defanged links, VirusTotal/URLhaus/MalwareBazaar lookup links, copyable JSON report. The built page has a CSP with `connect-src 'none'`.
- CLI `dist-cli/mailsleuth.js` printing JSON (`--compact`, stdin with `-`).
- Vitest suite (unit + end-to-end on samples), Playwright drive script (`npm run screenshots`), CI workflow, manual GitHub Pages workflow.

### Notes for the next contributor
- Samples are generated by `node scripts/make-samples.ts`; edit that script, not the `.eml` files.
- Scoring weights live in `POINTS` and the finding catalog in `src/core/analyze.ts`; tests in `test/analyze.test.ts` pin the expected findings per sample.
- A second-opinion review hardened the parsers against hostile input (quadratic regex, prototype-named and huge-index MIME parameters, `data-href`, `java&#10;script:` links, fake redirect-wrapper hosts, forged Authentication-Results). Each case has a regression test; keep adding one per new parser.
- Known gaps are listed under Limitations and Roadmap in the README.
