# Security policy

## What counts as a security issue

mailsleuth promises that the email you analyze stays on your machine and that analyzing it is harmless. Please report privately anything that breaks that:

- the page or CLI sending any data over the network, or a way around the page's Content-Security-Policy (`connect-src 'none'`),
- script, markup or styles from an email running or rendering in the page,
- a link from an email becoming clickable or opening something,
- an input that crashes the CLI or freezes the browser tab (for example quadratic parsing),
- the displayed text being reordered or hidden so a warning shows something other than the email's content.

## The browser extension

The extension (`extension/`, `src/extension/`) is held to the same promise. What it is allowed to do, and what should be reported if it does more:

- **Permissions:** a content script on `https://mail.google.com/*` and nothing else. The manifest has no `permissions` or `host_permissions` entries (no tabs, storage, cookies, history, downloads or background worker); CI fails if any appear.
- **Network:** one same-origin request per click, from the Gmail tab to Gmail's own "Download message" URL for the message clicked (`mode: 'same-origin'`, so a redirect to another host fails). The message id is checked against a strict pattern before it goes into that URL.
- **No remote code:** everything is bundled from this repository; the extension pages' Content-Security-Policy is `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'none'; form-action 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'self' https://mail.google.com`.
- **Isolation:** the analysis and the result run in the extension's own page, framed into Gmail, not in Gmail's page. The content script never parses or renders the email; it only hands the downloaded bytes to that frame (`postMessage` addressed to the extension's origin), and the frame accepts messages only from Gmail's top window. Email text is rendered with `textContent` only, as on the web page.

Anything that makes the extension request another host, read Gmail data other than the message you clicked, keep data after the panel closes, or run script from an email is a security issue.

A phishing trick that mailsleuth does not detect, or a wrong score, is a normal bug: open a "Missed or wrong finding" issue with a synthetic example (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## How to report

Private vulnerability reporting is not enabled on this repository. Please open an issue titled "Security contact request", **without any details**, and the maintainer will reply with a private way to send them. Do not include real emails in any report; a synthetic message that reproduces the problem is enough.

This is a hobby project maintained in spare time: there is no bug bounty and no guaranteed response time, but reports are taken seriously and fixes are credited in the changelog if you wish.

## Supported versions

Only the latest commit on `main` is supported. There are no released packages.
