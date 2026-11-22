# mailsleuth

**A suspicious-email analyzer that explains every warning sign in plain English, and never lets the email leave your browser.**

Drop in an `.eml` or Outlook `.msg` file (or paste the source) and get forged senders, failed SPF/DKIM/DMARC, look-alike domains, disguised links (including the ones hidden inside an attached PDF or HTML file) and risky attachments, each with the evidence it found and what to do next. The same core runs as a JSON CLI for scripting.

![Recording of mailsleuth analyzing a synthetic parcel-delivery phishing sample: score 100, high risk, then scrolling through the reasons, sender and authentication sections](docs/demo.gif)

Built for regular people who want a second opinion on one email, and for SOC beginners who need to triage user-reported phishing and learn what each header means. It gives a score with reasons, never a verdict: passing every check does not make a message honest.

## Quickstart

Needs Node.js 22.12 or newer (what Vite and Vitest require; CI uses Node 22) and about 30 seconds.

```sh
git clone https://github.com/Habibeyilmazz/mailsleuth.git
cd mailsleuth
npm ci
npm run dev          # web app on http://localhost:4190
```

Then, on the start page:

- **Just looking?** Pick one of the nine synthetic samples (look-alike domain, macro invoice, CEO gift cards, a link hidden in a PDF, a Word file that loads a remote template, a clean newsletter for contrast, and more).
- **Your own email:** drop or choose its `.eml` or Outlook `.msg` file, or paste the message source (Gmail: ⋮ › Show original; Outlook: ⋯ › View › View message source). In Outlook for Windows you can drag a message from the list straight onto the page.
- **Only part of it?** Headers alone work; body text alone (no headers) gets only the link and wording checks. Files saved with a byte order mark, as UTF-16, or with CR-only line endings are read too.
- **Only the attachment?** A PDF, image, archive or program dropped on its own is refused rather than rated: analyze the email it came in, which also gives the file's SHA-256 for a lookup.

There is no hosted copy yet; `npm run build` gives a static `dist/` you can serve yourself (see [Static build](#static-build)).

More screenshots: [start page](docs/screenshots/home.png), [a full result](docs/screenshots/result.png), [an Outlook .msg file](docs/screenshots/msg-result.png), [a link hidden in a PDF attachment](docs/screenshots/pdf-link-result.png), [a Word file that loads a remote template](docs/screenshots/office-template-result.png), [phone, dark mode](docs/screenshots/mobile-result-dark.png).

### Command line

```sh
npm run build:cli
node dist-cli/mailsleuth.js samples/01-paypal-lookalike.eml          # pretty JSON
node dist-cli/mailsleuth.js samples/07-outlook-sign-request.msg       # Outlook .msg works the same way
cat message.eml | node dist-cli/mailsleuth.js --compact - | jq '.score, .level, [.findings[].id]'
node dist-cli/mailsleuth.js --markdown samples/06-user-report-forwarded.eml > report.md   # for a ticket
```

Real output for the CEO gift-card sample, trimmed with `jq`:

```console
$ node dist-cli/mailsleuth.js --compact samples/04-ceo-gift-cards.eml \
    | jq '{score, level, findings: [.findings[] | "\(.severity) +\(.points)  \(.title)"]}'
{
  "score": 59,
  "level": "high",
  "findings": [
    "high +25  The sender name shows a different email address",
    "medium +12  Replies would go to a different domain",
    "medium +12  Mentions payments, gift cards or bank-detail changes",
    "low +5  Pressure to act quickly or quietly",
    "low +5  Delivery timestamps go backwards"
  ]
}
```

### Markdown report for a ticket

"Copy Markdown report" on the result page, or `--markdown` in the CLI (the two give the same text), writes a report you can paste into a ticket, a chat or case notes: score and verdict, sender, every reason with its evidence, authentication, delivery path, links, attachments with SHA-256, an "Observables" block (sender domains, link hosts and URLs, hashes, one per line) and what to do next. An attached email gets its own report one heading level down. Links and domains are defanged (`hxxps://evil[.]example`), and all text taken from the email is put in code spans, so a display name such as `[Support](https://…)` or an `<img>` in a subject cannot turn into a live link or image where the report is rendered. Like the page, it lists at most 200 items per section and says how many the JSON report has beyond that.

```console
$ node dist-cli/mailsleuth.js --markdown samples/04-ceo-gift-cards.eml | head -12
# Email report: `Quick favour - are you at your desk?`

**Score 59/100: High risk.** Several strong signs of phishing or fraud.

Warning signs, not a verdict: attackers can pass every check, and legitimate mail can trip some.

## Message

- From: `Dana Whitfield <dana.whitfield@northwind-traders.example> <ceo.office.dw@quickmail-hub.example>`
- Reply-To: `dwhitfield.exec@secure-reply.example`
- Return-Path: `ceo.office.dw@quickmail-hub.example`
- To: `Sam Okafor <sam.okafor@northwind-traders.example>`
```

The JSON contains the score, level, every finding (title, explanation, evidence), the parsed authentication results, delivery hops, links, attachments with SHA-256, and the full analysis of any attached email. The exit code is 0 whenever an analysis was printed, whatever the risk level, and 2 for unreadable, empty, oversized or non-email input or bad options (`--compact` with `--markdown`) (with a one-line message on stderr), so scripts should read `.level` or `.score` rather than the exit code.

### Static build

```sh
npm run build        # web app in dist/, CLI in dist-cli/
npm run preview      # serves dist/ on http://localhost:4191
```

`dist/` is a plain static site with relative paths; open it from any web server (opening `index.html` straight from disk does not work, because browsers block module scripts on `file://`). A manual GitHub Pages workflow is included (`.github/workflows/pages.yml`, run it from the Actions tab once Pages is set to "GitHub Actions").

## What it checks

| Area | Checks |
| --- | --- |
| Sender | From vs Reply-To vs Return-Path domains; more than one From address; a different email address hidden in the display name; brand names in the display name on a non-brand domain (also spelled with look-alike letters, or a capital I for l as in "PaypaI"); official-sounding names on free webmail |
| Domains | Look-alikes of 44 bundled brands: homoglyphs from Cyrillic/Greek, digit swaps (paypa1), one-letter typos, brand names inside someone else's domain (paypal.com.evil.example); punycode (`xn--`) decoded and shown; domain endings often seen in abuse reports |
| Authentication | SPF, DKIM, DMARC, ARC and Microsoft `compauth` from `Authentication-Results`, each explained in plain English; DMARC alignment; only the topmost header is trusted, and only when its server matches the newest `Received` hop (a header without a server name only behind a Microsoft 365 hop); earlier ones are shown as unverifiable |
| Delivery path | Every `Received` hop on a timeline with the delay since the previous hop; timestamps that go backwards are flagged |
| Links | Text that shows one site while linking to another (a file name such as `Report.pdf` is not a site, and the sender's own site behind a known mailing service's click tracking, such as Mailchimp or SendGrid, is a note rather than a warning); an email address shown over a `mailto:` link to another domain; Microsoft Safe Links, Proofpoint URL Defense (v2/v3), Google and Facebook redirects unwrapped before checking; shorteners; bare and disguised IP addresses (`http://3325256727/`); `user@host` tricks; `data:`, `javascript:` and `vbscript:` links; `file:` links, `\\server\share` paths and Windows handlers such as `search-ms:` and `ms-msdt:` (they open a share or a program; a share can receive the Windows login hash); open redirects; direct links to risky file types. Links inside PDF and HTML attachments get the same checks and are marked with the file they came from (see below) |
| Attachments | SHA-256 of each file, including files uuencoded into the message text (`begin 644 name`, which Thunderbird still shows as an attachment); type detected from content, not the name; VBA macros found by structure (OOXML `vbaProject.bin`, OLE `_VBA_PROJECT`); double extensions; hidden right-to-left characters; executables and scripts, ISO/IMG/VHD, LNK, OneNote, HTML/SVG; ZIP contents listed, risky entries and password protection flagged; password-protected Office documents; content that does not match the extension; in PDFs: JavaScript, Launch actions (start a program), embedded files, and encryption that hides the PDF's links; in Word/Excel/PowerPoint files: templates or objects loaded from a web address when the file opens (template injection, "Follina") |
| Links inside attachments | The "your document is attached" lure keeps the email itself clean and puts the real link in the attachment. mailsleuth reads link actions (`/URI`) from PDFs, both in plain objects and in the compressed object streams most current PDF writers use, and from HTML/SVG attachments it takes `<a>` links, form targets, and every bare URL in the file (script redirects, `<meta>` refreshes), and from Word/Excel/PowerPoint files every external link their relationship parts declare. Each appears under Links with "Inside the attachment …", and a note lists how many links each attachment has |
| Language | English phrases for credential phishing, money requests (gift cards, bank-detail changes), urgency/secrecy and threats; every match is quoted |
| Forwarded reports | An email attached as `message/rfc822`, as any file named `.eml`, or as an Outlook `.msg` file (how users report phishing) gets its own full analysis; in the UI, "Analyze attached email" opens it |
| Outlook `.msg` | Read without Outlook: the internet headers Outlook kept, every stored body (plain text, HTML, and compressed RTF, including HTML encapsulated in it as in most `.msg` files; all are checked because Outlook may show any of them), attachments and attached messages. The message is rebuilt as MIME and goes through every check above. Without stored internet headers (drafts, sent items, some internal mail), the sender, recipients and subject Outlook stored are used and the report says that authentication could not be checked. A damaged file (broken sector chain, failed RTF checksum) is refused rather than half-read |

Each finding adds points by severity (high 25, medium 12, low 5, capped at 100): 0–19 is low risk, 20–49 suspicious, 50+ high risk. The page shows each finding's share of the score, what it means, the exact evidence, things in the email's favour, and what to do next. It never says an email is safe or malicious: passing every check does not make a message honest, and legitimate mail can trip some checks.

## Privacy

- No network requests. The built page ships a Content-Security-Policy with `connect-src 'none'`, so the browser itself blocks any attempt to send data; CI checks the policy is present.
- No fonts, analytics or CDNs are loaded.
- Links in the email are shown defanged (`hxxps://evil[.]example`) and are never clickable.
- Invisible text-direction characters (U+202A-202E, U+2066-2069) from the email are shown as markers like `⟨U+202E⟩` instead of reordering what you read; the CLI and "Copy JSON report" write them, and C1 control characters, as `\uXXXX` escapes.
- The VirusTotal, URLhaus and MalwareBazaar buttons are ordinary links that you choose to click. They send only that one URL, host name or hash to that service, never the email.

## How it works

```
src/core/      shared by web and CLI, no dependencies
  mime.ts        MIME parser: header unfolding, RFC 2047/2231, multipart, base64/QP
  received.ts    Received headers -> ordered hops with delays
  auth.ts        Authentication-Results / ARC parser and plain-English explanations
  domains.ts     registrable domain, brand look-alike and homoglyph detection
  punycode.ts    RFC 3492 decoder
  msg.ts         Outlook .msg: Compound File reader, MAPI properties, compressed RTF, HTML-in-RTF -> MIME
  urls.ts        link extraction, wrapper unwrapping, link tricks
  attachments.ts magic-byte sniffing, ZIP central directory, macro detection
  pdf.ts         PDF link actions, JavaScript/Launch/embedded-file markers, Flate object streams
  office.ts      Word/Excel/PowerPoint external links and remote templates from _rels/*.rels
  language.ts    phrase patterns
  analyze.ts     runs everything, scores, writes next steps
  report.ts      defanged Markdown report (page button and CLI --markdown)
src/web/       vanilla TypeScript UI (DOM built with textContent only)
src/cli.ts     Node CLI
samples/       synthetic emails, generated by scripts/make-samples.ts
```

Raw input is kept as a byte-per-character string so MIME offsets stay exact; text is decoded per part with `TextDecoder`. SHA-256 uses Web Crypto and PDF object streams are inflated with `DecompressionStream`, both available in browsers and Node. The only dependencies are dev tools (Vite, Vitest, TypeScript, Playwright).

## When to use something else

mailsleuth is a local first look at one message. Other tools do some jobs better:

| Tool | What it is | Use it instead when |
| --- | --- | --- |
| [Microsoft Message Header Analyzer](https://github.com/microsoft/MHA) | Open-source header viewer from Microsoft, as a web page and an Outlook add-in | You are in Outlook / Microsoft 365 and want Microsoft's own anti-spam headers decoded; it reads headers only, not links or attachments |
| [Google Admin Toolbox Messageheader](https://toolbox.googleapps.com/apps/messageheader/) | Paste headers, see hops, delays and SPF/DKIM/DMARC | You only have headers and want a quick second view from Google's side |
| [eml_analyzer](https://github.com/ninoseki/eml_analyzer) | Open-source web app you host, analyzes `.eml` bodies, attachments and indicators | You want automatic reputation lookups (VirusTotal, urlscan.io and others) and are fine sending indicators to those services |
| A malware sandbox (for example ANY.RUN, Joe Sandbox, CAPE) | Opens attachments and links in an instrumented machine | You need to know what an attachment or page actually does. mailsleuth never opens, runs or fetches anything |
| Your mail provider's "Report phishing" button | Sends the message to the people who can block the sender | Always, in addition to any analysis. At work, follow your security team's reporting process first |

What mailsleuth adds: the whole message (headers, body, links and attachment structure) in one report, `.msg` support without Outlook, every point of the score explained, and no network access at all, so it is usable on mail you may not upload anywhere.

## Samples

`samples/` holds nine synthetic emails written for this project: a PayPal look-alike with a Safe Links-wrapped punycode link, an invoice with a macro document and an HTML attachment, a clean newsletter, a CEO gift-card request, a parcel notice full of link tricks, a user report that forwards the first one as an attachment, a fake signature request saved as an Outlook `.msg` file (body stored as compressed RTF, like most real ones), and a calm "here is the rate sheet" email that passes SPF, DKIM and DMARC and whose only link, to a Microsoft look-alike, is inside the attached PDF (in a compressed object stream, written by `scripts/pdf.ts`), and an equally calm "updated contract" whose Word file has no macro but loads its template from a web server, with a reply address shown over a `mailto:` link to a look-alike domain. The `.msg` sample is written by `scripts/msg.ts`; Python's `extract-msg` reads it with the same subject, headers, HTML and attachment hash. All domains are reserved (`.example`, `example.net`), all IPs are from documentation ranges, and the attachments contain only placeholder text. One sample links to a `bit.ly` path made up for this project to demonstrate shortener detection; the app never makes it clickable. Regenerate them with `node scripts/make-samples.ts` (Node 22.18+).

## Development

```sh
npm run typecheck
npm test                 # Vitest unit and end-to-end tests on the samples
npm run fuzz             # timing fuzz: hostile 60 KB inputs must each analyze in under 500 ms (about a minute)
npm run build
npm run e2e -- chromium   # main journey (samples, file picker, paste) served from /mailsleuth/ like Pages; page must match the CLI; axe-core accessibility check, light and dark
npm run screenshots      # drives the built app in Chromium (Playwright), fails on console errors or external requests
npm run demo             # re-records docs/demo.gif from the built app (needs ffmpeg)
```

CI runs `npm run e2e` in Chromium, Firefox and WebKit (Playwright's builds, not the Safari app), with the browser set to a non-UTC time zone.

## Limitations

- Brand list, abused-TLD list and multi-label suffixes (`co.uk`) are small hand-curated lists, not the full Public Suffix List or Unicode confusables table.
- HTML is scanned with regular expressions, not a DOM parser; badly malformed markup can hide a link.
- Ten mailing services' click trackers are known (Mailchimp, SendGrid, HubSpot, Amazon SES and others in `src/core/data.ts`). A newsletter sent through another service, with its own site as the link text, is still reported as "Link text shows one site but goes to another".
- Language checks are English only.
- Archives are listed, not unpacked: macros inside nested archives are not detected and files inside a ZIP are not searched for links. In Office documents the link targets are read but not the text shown over them, so a text/link mismatch inside a document is not flagged.
- PDFs are scanned for link actions, not parsed in full: an encrypted PDF (including the common kind that opens without a password) is reported as encrypted but its links cannot be read; a link stored as an indirect reference, in a PDF form's submit action, or written only as page text or in a QR code image is missed. JavaScript in an HTML attachment is not run, so a link it builds at run time (from `atob(...)` or string pieces) is missed.
- `.msg` files: OLE-object and by-reference (cloud link) attachments are named in the report but not extracted, and the SHA-256 of an email attached inside a `.msg` is of the rebuilt MIME copy, not of any original file. Ordinary attachments hash exactly as in the `.eml`.
- `Received` headers below your own provider can be forged; the timeline shows them as written.
- A `Received` date without a time zone, or with a zone name RFC 5322 does not define (such as `CET` without a numeric offset), shows as "no readable date" rather than a guess.
- Very large inputs cost memory: a 10 MB email of 450,000 distinct links takes about 3 s and 1 GB in the CLI, whose JSON then lists every link.
- The page lists at most 200 headers, hops, links, attachments, MIME parts, ZIP entries or evidence lines per section and says how many it left out; findings and "Copy JSON report" cover all of them.
- Authentication results are only counted in the email's favour when the checking server matches the newest `Received` hop. Setups where a separate filtering service checks mail before an internal server (or Gmail's "by" an IP address only, followed by a different host) can show genuine results as unverified; that removes a reassurance but never adds points.

## Roadmap

Ideas, not promises; the order is roughly what would help most.

- A hosted copy: the manual Pages workflow is ready, Pages just has to be switched on for the repository
- Links inside files in ZIP archives (Office documents already inflate their entries with `DecompressionStream`)
- Reading links in encrypted PDFs that open without a password (needs MD5/RC4 for older PDFs and AES for newer ones)
- QR codes in images and PDFs ("scan to sign in"), which needs an image decoder in the browser
- Full Public Suffix List and a larger confusables table
- More languages for the phrase checks

## Contributing

Bug reports, missed or wrong findings, and small focused pull requests are welcome; [CONTRIBUTING.md](CONTRIBUTING.md) has the setup and the few rules (every parser change gets a test, every new regex goes through `npm run fuzz`). **Never attach a real email to an issue**: rebuild the trick in a synthetic message with `example` domains, as the samples do.

Security problems in mailsleuth itself (something that makes data leave the page, runs script from an email, or freezes the tab): see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © Habibeyilmazz
