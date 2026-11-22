# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed (round 5: reliability and tests)
Each bug below was reproduced first, then got a failing test, then the fix.
- Dropping the attachment itself (a PDF, image, ZIP, program) instead of the email gave "Low risk: No strong warning signs found". Files whose signature says they are not text are now refused with "this looks like a PDF, not an email" (page error, CLI exit 2). HTML and RTF are still read; `MZ` counts as a program only when binary bytes follow, so a pasted "MZ Bank: …" is still analyzed.
- The CLI rated an empty or whitespace-only file "low"; it now says the input is empty and exits 2 (the page already refused it).
- Encodings and line endings that real files have: a UTF-8 byte order mark hid the From header; source saved as UTF-16 (Notepad "Unicode") and CR-only files scored 0; `\r\r\n` endings (CRLF re-saved in text mode) lost links and an attachment. Line endings are normalized only when the first line has a lone CR, so a stray CR inside a well-formed message keeps attachment hashes intact.
- Received dates are parsed by RFC 5322 rules instead of `Date.parse`, which read a date without a zone as the viewer's local time (hop delays and the "time travel" finding changed with the computer's time zone), rejected `+0100 CET` without parentheses and `+01:00`, and turned 31 February into 3 March. A date with no zone or a non-RFC zone name now shows as "no readable date".
- A multi-byte character split across two adjacent RFC 2047 encoded words (common in long subjects) showed as U+FFFD; adjacent words in one charset are now joined as bytes before decoding, as mail clients do.
- Quoted-printable `=` followed by spaces before the line break (RFC 2045 transport padding) was not a soft break, so a link split there was missed.
- Filter evasions the reader never sees: zero-width characters, soft hyphens, full-width letters and Cyrillic/Greek look-alikes in the display name (`Pay<U+200B>Pal`, `PаyPal`, `Mіcrosoft`) or in the wording (`ver&shy;ify your acc<U+200B>ount`), words split by inline tags (`ver<span>ify</span>`), and a zero-width space in `invoice.pdf<U+200B>.exe` hid the brand, pressure-phrase and double-extension findings. These checks now compare text as it is displayed.

### Added (round 5)
- `npm run e2e` (`scripts/e2e.mjs`): the main journey (every sample, the attached email in sample 06, the file picker with `.eml` and `.msg`, a dropped PDF, a paste) with the build served from `/mailsleuth/` the way GitHub Pages serves it, the browser set to a non-UTC time zone, and every page result compared with what the CLI computes in Node (score, reasons, delivery dates, attachment hashes). CI runs it in Playwright's Chromium, Firefox and WebKit; it also fails on console errors and on any request leaving the page's origin.
- CI runs the unit tests with `TZ=Asia/Kolkata` (runners are UTC, which hides local-time bugs).

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
- Reliability round (round 5): first CI run of the e2e passed in all three engines, so no Firefox/WebKit-specific bug was found; Playwright's WebKit is not the Safari app. GitHub Pages itself was still never enabled (only simulated by the sub-path server). No real Outlook-made `.msg` was available, so that gap is unchanged; OLE-object and cloud-link attachments are still named, not extracted (a feature, not a bug). Codex was at its usage limit this round, so it did not review these changes. Probed and found fine: 5 MB single-line bodies, 20,000 links, 5,000 attachments, 300 nested multiparts, decimal/hex/octal IP hosts, backslash and userinfo URL tricks, RFC 2231 and encoded-word file names. Left as is: an inner multipart reusing its parent's boundary (clients disagree), a `<meta http-equiv=refresh>` target is not extracted, and a `<form action>` is listed as a link but a form in an email adds no points of its own.
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
