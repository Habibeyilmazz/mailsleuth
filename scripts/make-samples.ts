// Generates the synthetic sample emails in samples/. Run: node scripts/make-samples.ts
// Every domain is reserved (.example / example.net), every IP is from documentation ranges,
// and attachments contain only harmless placeholder text. Nothing here is real mail.
import { writeFileSync } from 'node:fs';
import { compressRtf, makeMsg } from './msg.ts';
import { makeZip } from './zip.ts';

const b64 = (data: string | Uint8Array) =>
  Buffer.from(data).toString('base64').replace(/.{76}/g, '$&\n').trim();

const docm = makeZip([
  { name: '[Content_Types].xml', data: '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>' },
  { name: 'word/document.xml', data: '<w:document><!-- mailsleuth synthetic sample: no real content --></w:document>' },
  { name: 'word/vbaProject.bin', data: 'SYNTHETIC PLACEHOLDER - not a real VBA project, contains no code' },
]);

const fakeLoginHtml = `<!doctype html>
<html><body>
<h1>SYNTHETIC SAMPLE</h1>
<p>This file imitates the HTML "remittance" attachments used for credential phishing. It is inert.</p>
<form action="https://collect.invalid/submit" method="post"><input name="email"><input name="password" type="password"></form>
</body></html>`;

const samples: Record<string, string> = {
  '01-paypal-lookalike.eml': `Return-Path: <bounce-7731@mailer.paypa1-secure.example>
Received: from mx1.example.net (mx1.example.net [192.0.2.10])
 by mailstore.example.net with LMTP id 88AB12; Tue, 10 Nov 2026 09:14:52 +0000
Received: from mailer.paypa1-secure.example (mailer.paypa1-secure.example [203.0.113.45])
 by mx1.example.net with ESMTPS id 4f1c2d; Tue, 10 Nov 2026 09:14:50 +0000
Received: from [10.0.0.12] (unknown [198.51.100.77])
 by mailer.paypa1-secure.example with ESMTPSA id 77aa; Tue, 10 Nov 2026 09:06:31 +0000
Authentication-Results: mx1.example.net;
 spf=softfail (example.net: domain of transitioning bounce-7731@mailer.paypa1-secure.example does not designate 203.0.113.45 as permitted sender) smtp.mailfrom=bounce-7731@mailer.paypa1-secure.example;
 dkim=none;
 dmarc=none header.from=paypa1-secure.example
From: "PayPal" <service@paypa1-secure.example>
Reply-To: <case-review@account-help.example>
To: alex@example.net
Subject: =?UTF-8?Q?Your_account_has_been_limited_=E2=80=93_action_required?=
Date: Tue, 10 Nov 2026 09:06:30 +0000
Message-ID: <synthetic-0001@paypa1-secure.example>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="b1"

--b1
Content-Type: text/plain; charset=utf-8

Dear Customer,

We noticed unusual sign-in activity and your account has been limited.
Please verify your account within 24 hours or it will be permanently suspended.

Verify now: https://www.paypal.com/signin

PayPal Security Team
--b1
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: quoted-printable

<html><body style=3D"font-family:Arial">
<p>Dear Customer,</p>
<p>We noticed <b>unusual sign-in activity</b> and your account has been limite=
d.</p>
<p>Please verify your account within 24 hours or it will be permanently suspe=
nded.</p>
<p><a href=3D"https://nam12.safelinks.protection.outlook.com/?url=3Dhttps%3A%2F=
%2Fxn--pypal-4ve.example%2Fsignin%3Fsession%3D8812&amp;data=3D05%7C01&amp;reser=
ved=3D0">https://www.paypal.com/signin</a></p>
<p><a href=3D"http://paypal.com.session-review.example/login?id=3D8812">Review =
recent activity</a></p>
<p>PayPal Security Team</p>
</body></html>
--b1--
`,

  '02-invoice-macro.eml': `Return-Path: <billing@contoso-supplies.example>
Received: from smtp.contoso-supplies.example (smtp.contoso-supplies.example [198.51.100.20])
 by mx1.example.net with ESMTPS id 99c1; Wed, 11 Nov 2026 14:02:07 +0000
Received: from workstation-14 (unknown [10.20.0.14])
 by smtp.contoso-supplies.example with ESMTPSA id 1a2b; Wed, 11 Nov 2026 14:02:05 +0000
Authentication-Results: mx1.example.net;
 spf=pass (example.net: domain of billing@contoso-supplies.example designates 198.51.100.20 as permitted sender) smtp.mailfrom=billing@contoso-supplies.example;
 dkim=pass header.i=@contoso-supplies.example header.s=s1 header.b=AbCdEf12;
 dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=contoso-supplies.example
From: "Contoso Supplies Billing" <billing@contoso-supplies.example>
Reply-To: "Accounts" <payments@contoso-billing.example.org>
To: "Accounts Payable" <ap@example.net>
Subject: Invoice 88231 overdue - updated payment details
Date: Wed, 11 Nov 2026 14:02:03 +0000
Message-ID: <synthetic-0002@contoso-supplies.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="mix"

--mix
Content-Type: text/plain; charset=us-ascii

Hello,

Our records show invoice 88231 is overdue. Please note we have changed our bank details,
see the attached invoice and remittance form. Kindly process the payment urgently.

If the document shows a security warning, click "Enable content" to view it.

Regards,
Contoso Supplies Billing
--mix
Content-Type: application/vnd.ms-word.document.macroEnabled.12; name="Invoice_88231.docm"
Content-Disposition: attachment; filename="Invoice_88231.docm"
Content-Transfer-Encoding: base64

${b64(docm)}
--mix
Content-Type: text/html; name="Remittance_Advice.pdf.html"
Content-Disposition: attachment; filename="Remittance_Advice.pdf.html"
Content-Transfer-Encoding: base64

${b64(fakeLoginHtml)}
--mix--
`,

  '03-newsletter-legit.eml': `Return-Path: <bounces+4471@mail.northwind-garden.example>
Received: from o1.mail.northwind-garden.example (o1.mail.northwind-garden.example [198.51.100.150])
 by mx1.example.net with ESMTPS id 3c3c; Thu, 12 Nov 2026 07:30:04 +0000
Received: by o1.mail.northwind-garden.example with SMTP id 0x9; Thu, 12 Nov 2026 07:30:01 +0000
Authentication-Results: mx1.example.net;
 spf=pass smtp.mailfrom=bounces+4471@mail.northwind-garden.example;
 dkim=pass header.i=@northwind-garden.example header.s=nw1;
 dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=northwind-garden.example;
 arc=none
From: "Northwind Gardening Club" <news@northwind-garden.example>
To: alex@example.net
Subject: =?UTF-8?B?Tm92ZW1iZXIgaW4gdGhlIGdhcmRlbiDwn4yx?=
Date: Thu, 12 Nov 2026 07:30:00 +0000
Message-ID: <synthetic-0003@northwind-garden.example>
List-Unsubscribe: <https://northwind-garden.example/unsubscribe?u=4471>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="nw"

--nw
Content-Type: text/plain; charset=utf-8

Hi Alex,

November is the time to plant garlic and spring bulbs. This month:
- Five bulbs that survive a late frost
- How to store dahlia tubers over winter

Read online: https://northwind-garden.example/newsletter/2026-11

You are receiving this because you joined the Northwind Gardening Club.
Unsubscribe: https://northwind-garden.example/unsubscribe?u=4471
--nw
Content-Type: text/html; charset=utf-8

<html><body>
<p>Hi Alex,</p>
<p>November is the time to plant garlic and spring bulbs. This month:</p>
<ul><li>Five bulbs that survive a late frost</li><li>How to store dahlia tubers over winter</li></ul>
<p><a href="https://northwind-garden.example/newsletter/2026-11">Read online</a></p>
<p><small>You are receiving this because you joined the Northwind Gardening Club.
<a href="https://northwind-garden.example/unsubscribe?u=4471">Unsubscribe</a></small></p>
</body></html>
--nw--
`,

  '04-ceo-gift-cards.eml': `Return-Path: <ceo.office.dw@quickmail-hub.example>
Received: from mx1.example.net (mx1.example.net [192.0.2.10])
 by mailstore.example.net with LMTP id 1d1d; Fri, 13 Nov 2026 16:41:12 +0000
Received: from out.quickmail-hub.example (out.quickmail-hub.example [203.0.113.200])
 by mx1.example.net with ESMTPS id 2e2e; Fri, 13 Nov 2026 16:41:10 +0000
Received: from relay7.quickmail-hub.example (relay7.quickmail-hub.example [203.0.113.207])
 by out.quickmail-hub.example with ESMTP id 3f3f; Fri, 13 Nov 2026 16:58:40 +0000
Authentication-Results: mx1.example.net;
 spf=pass smtp.mailfrom=ceo.office.dw@quickmail-hub.example;
 dkim=pass header.i=@quickmail-hub.example;
 dmarc=pass header.from=quickmail-hub.example
From: "Dana Whitfield <dana.whitfield@northwind-traders.example>" <ceo.office.dw@quickmail-hub.example>
Reply-To: <dwhitfield.exec@secure-reply.example>
To: "Sam Okafor" <sam.okafor@northwind-traders.example>
Subject: Quick favour - are you at your desk?
Date: Fri, 13 Nov 2026 16:58:38 +0000
Message-ID: <synthetic-0004@quickmail-hub.example>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Sam,

I'm stuck in back-to-back meetings and need a favour. Please buy 6 gift cards
($200 each) for a client appreciation event today. Keep this between us for now,
it's a surprise. Scratch the codes and send me photos ASAP.

Dana
Sent from my phone
`,

  '05-parcel-redelivery.eml': `Received: from AM0PR01MB1234.eurprd01.prod.example.net (2001:db8::25) by
 AM0PR01MB9999.eurprd01.prod.example.net with HTTPS; Mon, 16 Nov 2026 08:01:15 +0000
Received: from mta.dhl-parcel-tracking.example (203.0.113.80) by
 AM0PR01MB1234.eurprd01.prod.example.net (2001:db8::25) with Microsoft SMTP Server; Mon, 16 Nov 2026 08:01:13 +0000
Authentication-Results: spf=fail (sender IP is 203.0.113.80)
 smtp.mailfrom=dhl-parcel-tracking.example; dkim=none (message not signed)
 header.d=none;dmarc=fail action=quarantine
 header.from=dhl-parcel-tracking.example;compauth=fail reason=000
From: "DHL Express" <noreply@dhl-parcel-tracking.example>
To: alex@example.net
Subject: Delivery attempt failed - reschedule within 48 hours
Date: Mon, 16 Nov 2026 08:01:09 +0000
Message-ID: <synthetic-0005@dhl-parcel-tracking.example>
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body>
<p>We were unable to deliver your parcel. A customs fee of 1.99 EUR is pending.</p>
<p>Reschedule within 48 hours or the parcel will be returned:</p>
<p><a href="https://bit.ly/mailsleuth-synthetic-sample">Track my parcel</a></p>
<p><a href="https://www.dhl.com@203.0.113.7/redelivery">https://www.dhl.com/redelivery</a></p>
<p><a href="http://3325256727/fee">Pay customs fee</a></p>
<p><a href="https://urldefense.proofpoint.com/v2/url?u=https-3A__dhl-2Dredelivery.example_label.zip&amp;d=DwMFaQ&amp;c=x">Download shipping label</a></p>
<p><a href="data:text/html;base64,PGgxPlN5bnRoZXRpYyBzYW1wbGU8L2gxPg==">View receipt</a></p>
</body></html>
`,
};

// 06: what a SOC inbox receives: a user forwarding the suspicious mail as an attachment.
samples['06-user-report-forwarded.eml'] = `From: "Alex Rivera" <alex@example.net>
To: "Security Team" <phishing-reports@example.net>
Subject: Fwd: Your account has been limited - is this real?
Date: Tue, 10 Nov 2026 09:20:00 +0000
Message-ID: <synthetic-0006@example.net>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="fwd"

--fwd
Content-Type: text/plain; charset=utf-8

Hi, I got this and I'm not sure if it's legit. Didn't click anything.
Alex
--fwd
Content-Type: message/rfc822
Content-Disposition: attachment; filename="Your account has been limited.eml"

${samples['01-paypal-lookalike.eml']}
--fwd--
`;

for (const [name, body] of Object.entries(samples)) writeFileSync(new URL(`../samples/${name}`, import.meta.url), body);
console.log(`wrote ${Object.keys(samples).length} samples`);

// 07: the same kind of lure saved from Outlook as a .msg file. Like most real .msg files, the
// formatted body exists only as compressed RTF with the original HTML encapsulated in it.
const lureHeaders = `Received: from mx1.example.net (mx1.example.net [192.0.2.10])
 by mailstore.example.net with LMTP id 61CD03; Wed, 11 Nov 2026 14:02:19 +0000
Received: from relay.sign-docs.example (relay.sign-docs.example [203.0.113.88])
 by mx1.example.net with ESMTPS id 9e0b44; Wed, 11 Nov 2026 14:02:17 +0000
Authentication-Results: mx1.example.net;
 spf=fail (example.net: domain of notice@docusign-mail.example does not designate 203.0.113.88 as permitted sender) smtp.mailfrom=notice@docusign-mail.example;
 dkim=none;
 dmarc=fail (p=reject) header.from=docusign-mail.example
From: "DocuSign via eSignature" <notice@docusign-mail.example>
To: "Alex Rivera" <alex@example.net>
Subject: Completed: Please review and sign - Q4 Payroll Adjustment
Date: Wed, 11 Nov 2026 14:02:10 +0000
Message-ID: <synthetic-0007@docusign-mail.example>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="orig"
`;
const lureHtmlLink = 'https://sign-docs.example/view?ti=7f3a';
const lureRtf = String.raw`{\rtf1\ansi\ansicpg1252\fromhtml1 \deff0{\fonttbl
{\f0\fswiss Arial;}
{\f1\fmodern Courier New;}}
{\colortbl\red0\green0\blue0;\red0\green0\blue255;}
\uc1\pard\plain\deftab360 \f0\fs20 
{\*\htmltag19 <html>}
{\*\htmltag50 <body>}\htmlrtf \lang1033 \htmlrtf0 
{\*\htmltag64 <p>}\htmlrtf {\htmlrtf0 SYNTHETIC SAMPLE. Alex Rivera, a document is waiting for your signature: Q4 Payroll Adjustment.\htmlrtf\par}\htmlrtf0
{\*\htmltag72 </p>}
{\*\htmltag64 <p>}\htmlrtf {\htmlrtf0 Review and sign within 24 hours or the request expires. Confirm your email to open the document.\htmlrtf\par}\htmlrtf0
{\*\htmltag72 </p>}
{\*\htmltag64 <p>}{\*\htmltag84 <a href="${lureHtmlLink}">}\htmlrtf {\field{\*\fldinst{HYPERLINK "${lureHtmlLink}"}}{\fldrslt\cf1\ul \htmlrtf0 https://www.docusign.net/Signing/?ti=7f3a\htmlrtf }\htmlrtf0 }\htmlrtf0 {\*\htmltag92 </a>}
{\*\htmltag72 </p>}
{\*\htmltag64 <p>}\htmlrtf {\htmlrtf0 Questions? Do not reply to this email \endash  contact the sender.\htmlrtf\par}\htmlrtf0
{\*\htmltag72 </p>}
{\*\htmltag58 </body>}
{\*\htmltag27 </html>}}`;
const lureText = `SYNTHETIC SAMPLE. Alex Rivera, a document is waiting for your signature: Q4 Payroll Adjustment.

Review and sign within 24 hours or the request expires. Confirm your email to open the document.

https://www.docusign.net/Signing/?ti=7f3a <${lureHtmlLink}>

Questions? Do not reply to this email - contact the sender.
`;
const enc = new TextEncoder();
const msg = makeMsg({
  strings: {
    0x001a: 'IPM.Note',
    0x0037: 'Completed: Please review and sign - Q4 Payroll Adjustment',
    0x0c1a: 'DocuSign via eSignature',
    0x0c1f: 'notice@docusign-mail.example',
    0x5d01: 'notice@docusign-mail.example',
    0x0e04: 'Alex Rivera',
    0x007d: lureHeaders.replace(/\n/g, '\r\n'),
    0x1000: lureText.replace(/\n/g, '\r\n'),
    0x1035: '<synthetic-0007@docusign-mail.example>',
  },
  binaries: { 0x1009: compressRtf(enc.encode(lureRtf.replace(/\n/g, '\r\n'))) },
  longs: { 0x3fde: 20127 },
  times: { 0x0039: new Date('2026-11-11T14:02:10Z'), 0x0e06: new Date('2026-11-11T14:02:19Z') },
  recipients: [{ strings: { 0x3001: 'Alex Rivera', 0x39fe: 'alex@example.net', 0x3003: 'alex@example.net' }, longs: { 0x0c15: 1 } }],
  attachments: [
    {
      strings: { 0x3707: 'Payroll_Adjustment.htm', 0x3704: 'PAYROL~1.HTM', 0x370e: 'text/html' },
      binaries: { 0x3701: enc.encode(fakeLoginHtml) },
      longs: { 0x3705: 1 },
    },
  ],
});
writeFileSync(new URL('../samples/07-outlook-sign-request.msg', import.meta.url), msg);
console.log('wrote 07-outlook-sign-request.msg');
