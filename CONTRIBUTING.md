# Contributing to mailsleuth

Thanks for helping. Small, focused changes with a test are the easiest to review and merge.

## Never share a real email

Issues, pull requests and test fixtures are public. Do not attach or paste a real message, not even "redacted": headers carry names, addresses, IP addresses, internal host names and tracking IDs that are easy to miss.

Instead, rebuild the trick in a synthetic message:

- domains under `.example`, `.invalid` or `example.net` / `example.com` (reserved by RFC 2606),
- IP addresses from the documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
- attachments containing placeholder text only (never a real macro or executable),
- a made-up person, not a colleague or customer.

`scripts/make-samples.ts` shows how the bundled samples are written; a few lines of headers that reproduce the problem are usually enough.

## Setup

Node.js 22.12 or newer (the sample generator needs 22.18+ because it runs TypeScript directly).

```sh
npm ci
npm run dev            # http://localhost:4190
```

Before opening a pull request:

```sh
npm run typecheck
npm test
npm run fuzz           # needed if you touched a parser or added a regex
npm run build && npm run e2e -- chromium
```

`npm run e2e` needs Playwright's browsers (`npx playwright install chromium`). CI runs all of the above, plus the e2e in Firefox and WebKit.

## Rules of the codebase

- `src/core` has no runtime dependencies and makes no network requests. It runs in browsers and in Node; use Web APIs (`TextDecoder`, `crypto.subtle`) rather than Node modules there.
- Every parser change or new finding gets a test in `test/`. A bug fix starts with a failing test.
- Every new regex goes through `npm run fuzz`. Most past slowdowns were a `\s*`, `[^)]*` or `+` that restarts from every position of a long run.
- New findings go in the catalog in `src/core/analyze.ts` with a plain-English title, an explanation a non-expert understands, and the exact evidence. Severity sets the points (`POINTS`); keep the wording careful: a finding is a warning sign, never proof.
- The web UI builds the DOM with `textContent` only; never `innerHTML` with email content. Links from emails are shown defanged and are never clickable.
- Samples are generated: edit `scripts/make-samples.ts`, then run `node scripts/make-samples.ts`, and update the expected findings in `test/analyze.test.ts`.
- Keep `CHANGELOG.md` up to date under `[Unreleased]`.

## Reporting a missed or wrong finding

Use the "Missed or wrong finding" issue form. Include the synthetic message (or the relevant headers / HTML), what mailsleuth reported, and what you expected. False positives on legitimate mail are as useful as missed phishing.

## Security issues

See [SECURITY.md](SECURITY.md).
