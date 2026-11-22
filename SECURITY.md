# Security policy

## What counts as a security issue

mailsleuth promises that the email you analyze stays on your machine and that analyzing it is harmless. Please report privately anything that breaks that:

- the page or CLI sending any data over the network, or a way around the page's Content-Security-Policy (`connect-src 'none'`),
- script, markup or styles from an email running or rendering in the page,
- a link from an email becoming clickable or opening something,
- an input that crashes the CLI or freezes the browser tab (for example quadratic parsing),
- the displayed text being reordered or hidden so a warning shows something other than the email's content.

A phishing trick that mailsleuth does not detect, or a wrong score, is a normal bug: open a "Missed or wrong finding" issue with a synthetic example (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## How to report

Private vulnerability reporting is not enabled on this repository. Please open an issue titled "Security contact request", **without any details**, and the maintainer will reply with a private way to send them. Do not include real emails in any report; a synthetic message that reproduces the problem is enough.

This is a hobby project maintained in spare time: there is no bug bounty and no guaranteed response time, but reports are taken seriously and fixes are credited in the changelog if you wish.

## Supported versions

Only the latest commit on `main` is supported. There are no released packages.
