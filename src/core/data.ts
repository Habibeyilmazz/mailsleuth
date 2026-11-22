// Bundled reference lists. Small on purpose: they are read by humans in code review.

export interface Brand {
  name: string;
  /** Registrable domains the brand really sends mail / hosts links from. */
  domains: string[];
  /** Phrases that, in a sender's display name, claim to be this brand. Word-boundary, case-insensitive. */
  displayNames: string[];
}

export const BRANDS: Brand[] = [
  { name: 'PayPal', domains: ['paypal.com', 'paypal.me', 'paypalobjects.com'], displayNames: ['paypal'] },
  {
    name: 'Microsoft',
    domains: ['microsoft.com', 'microsoftonline.com', 'office.com', 'office365.com', 'outlook.com', 'live.com', 'hotmail.com', 'sharepoint.com', 'onmicrosoft.com', 'azure.com', 'microsoft365.com', 'msn.com', 'onedrive.com', 'skype.com', 'xbox.com'],
    displayNames: ['microsoft', 'office 365', 'office365', 'microsoft 365', 'outlook team', 'outlook web app', 'onedrive', 'sharepoint', 'azure'],
  },
  { name: 'Apple', domains: ['apple.com', 'icloud.com', 'me.com', 'mac.com'], displayNames: ['apple', 'apple id', 'icloud', 'itunes', 'app store'] },
  { name: 'Google', domains: ['google.com', 'gmail.com', 'googlemail.com', 'youtube.com', 'googleusercontent.com', 'withgoogle.com'], displayNames: ['google', 'gmail', 'google workspace', 'youtube'] },
  { name: 'Amazon', domains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.ca', 'amazon.co.jp', 'amazon.in', 'amazon.com.tr', 'amazonaws.com', 'aws.amazon.com', 'amazonses.com'], displayNames: ['amazon', 'amazon prime', 'aws'] },
  { name: 'Netflix', domains: ['netflix.com'], displayNames: ['netflix'] },
  { name: 'Meta', domains: ['facebook.com', 'facebookmail.com', 'fb.com', 'meta.com', 'instagram.com', 'whatsapp.com'], displayNames: ['facebook', 'meta', 'instagram', 'whatsapp'] },
  { name: 'LinkedIn', domains: ['linkedin.com'], displayNames: ['linkedin'] },
  { name: 'Dropbox', domains: ['dropbox.com', 'dropboxmail.com'], displayNames: ['dropbox'] },
  { name: 'DocuSign', domains: ['docusign.com', 'docusign.net'], displayNames: ['docusign'] },
  { name: 'Adobe', domains: ['adobe.com', 'adobesign.com', 'echosign.com'], displayNames: ['adobe', 'adobe sign', 'acrobat'] },
  { name: 'DHL', domains: ['dhl.com', 'dhl.de', 'dhl.co.uk'], displayNames: ['dhl', 'dhl express'] },
  { name: 'FedEx', domains: ['fedex.com'], displayNames: ['fedex'] },
  { name: 'UPS', domains: ['ups.com'], displayNames: ['ups', 'ups delivery'] },
  { name: 'USPS', domains: ['usps.com', 'usps.gov'], displayNames: ['usps', 'postal service'] },
  { name: 'Wells Fargo', domains: ['wellsfargo.com', 'wf.com'], displayNames: ['wells fargo'] },
  { name: 'Chase', domains: ['chase.com', 'jpmorgan.com', 'jpmorganchase.com'], displayNames: ['chase bank', 'jpmorgan', 'chase online'] },
  { name: 'Bank of America', domains: ['bankofamerica.com', 'bofa.com'], displayNames: ['bank of america'] },
  { name: 'Citi', domains: ['citi.com', 'citibank.com'], displayNames: ['citibank'] },
  { name: 'HSBC', domains: ['hsbc.com', 'hsbc.co.uk'], displayNames: ['hsbc'] },
  { name: 'American Express', domains: ['americanexpress.com', 'aexp.com'], displayNames: ['american express', 'amex'] },
  { name: 'Coinbase', domains: ['coinbase.com'], displayNames: ['coinbase'] },
  { name: 'Binance', domains: ['binance.com'], displayNames: ['binance'] },
  { name: 'Steam', domains: ['steampowered.com', 'steamcommunity.com'], displayNames: ['steam support', 'steam community'] },
  { name: 'eBay', domains: ['ebay.com', 'ebay.co.uk', 'ebay.de'], displayNames: ['ebay'] },
  { name: 'Walmart', domains: ['walmart.com'], displayNames: ['walmart'] },
  { name: 'IRS', domains: ['irs.gov'], displayNames: ['irs', 'internal revenue service'] },
  { name: 'X (Twitter)', domains: ['twitter.com', 'x.com'], displayNames: ['twitter'] },
  { name: 'Zoom', domains: ['zoom.us', 'zoom.com'], displayNames: ['zoom'] },
  { name: 'Slack', domains: ['slack.com'], displayNames: ['slack'] },
  { name: 'GitHub', domains: ['github.com', 'githubusercontent.com'], displayNames: ['github'] },
  { name: 'Spotify', domains: ['spotify.com'], displayNames: ['spotify'] },
  { name: 'Airbnb', domains: ['airbnb.com'], displayNames: ['airbnb'] },
  { name: 'Booking.com', domains: ['booking.com'], displayNames: ['booking.com'] },
  { name: 'Revolut', domains: ['revolut.com'], displayNames: ['revolut'] },
  { name: 'Stripe', domains: ['stripe.com'], displayNames: ['stripe'] },
  { name: 'Intuit', domains: ['intuit.com', 'quickbooks.com', 'turbotax.com'], displayNames: ['intuit', 'quickbooks', 'turbotax'] },
  { name: 'Mastercard', domains: ['mastercard.com'], displayNames: ['mastercard'] },
  { name: 'Visa', domains: ['visa.com'], displayNames: ['visa card', 'visa security'] },
  { name: 'Norton', domains: ['norton.com', 'nortonlifelock.com'], displayNames: ['norton 360', 'norton antivirus', 'norton security', 'norton lifelock', 'nortonlifelock'] },
  { name: 'McAfee', domains: ['mcafee.com'], displayNames: ['mcafee antivirus', 'mcafee security', 'mcafee total protection', 'mcafee support'] },
  { name: 'WeTransfer', domains: ['wetransfer.com'], displayNames: ['wetransfer'] },
  { name: 'Yahoo', domains: ['yahoo.com', 'yahoo.co.uk', 'ymail.com'], displayNames: ['yahoo'] },
  { name: 'Wise', domains: ['wise.com', 'transferwise.com'], displayNames: ['wise transfer', 'transferwise'] },
];

/**
 * TLDs that public abuse reports keep listing as over-represented in phishing and malware,
 * plus new gTLDs that read like file names (.zip, .mov). Not proof of anything on their own.
 */
export const ABUSED_TLDS = new Set([
  'zip', 'mov', 'top', 'xyz', 'click', 'link', 'work', 'cam', 'buzz', 'rest', 'gq', 'ml', 'cf', 'tk', 'ga',
  'country', 'kim', 'loan', 'men', 'review', 'stream', 'download', 'racing', 'win', 'bid', 'date', 'faith',
  'cyou', 'sbs', 'icu', 'quest', 'monster', 'lol', 'cfd', 'bond',
]);

export const URL_SHORTENERS = new Set([
  'bit.ly', 'bitly.com', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly',
  'shorturl.at', 'rb.gy', 'tiny.cc', 't.ly', 'v.gd', 's.id', 'lnkd.in', 'qrco.de', 'shorturl.com', 'bl.ink',
  'short.io', 'tinyurl.is', 'u.to', 'clck.ru', 'surl.li',
]);

export const FREE_MAIL = new Set([
  'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com', 'ymail.com',
  'aol.com', 'icloud.com', 'me.com', 'mail.com', 'gmx.com', 'gmx.net', 'gmx.de', 'web.de', 'proton.me',
  'protonmail.com', 'yandex.com', 'yandex.ru', 'mail.ru', 'zoho.com', 'tutanota.com', 'qq.com', '163.com',
]);

/**
 * shortcut: a hand-picked subset of the Public Suffix List (second-level registries).
 * Upgrade to the full PSL if users report wrong "organizational domain" grouping.
 */
export const MULTI_LABEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'ltd.uk', 'plc.uk', 'me.uk', 'com.au', 'net.au', 'org.au', 'gov.au',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'com.br', 'net.br', 'org.br', 'gov.br', 'com.tr', 'org.tr', 'gov.tr',
  'net.tr', 'edu.tr', 'co.nz', 'org.nz', 'co.za', 'org.za', 'com.mx', 'co.in', 'org.in', 'gov.in', 'com.cn',
  'net.cn', 'org.cn', 'com.sg', 'com.hk', 'co.kr', 'or.kr', 'com.ar', 'com.co', 'com.pl', 'co.il', 'com.my',
  'com.ua', 'com.ru', 'com.es', 'co.id', 'com.ph', 'com.vn', 'com.pk', 'com.eg', 'com.sa', 'co.th',
  // Hosting platforms where every subdomain belongs to a different customer (PSL "private" section).
  'github.io', 'gitlab.io', 'netlify.app', 'vercel.app', 'pages.dev', 'workers.dev', 'herokuapp.com',
  'azurewebsites.net', 'blogspot.com', 'web.app', 'firebaseapp.com', 'appspot.com', 'onrender.com',
  'glitch.me', 'wixsite.com', 'weebly.com', 'ngrok.io', 'ngrok-free.app', 'trycloudflare.com', 'r2.dev',
  'cloudfront.net', 'webflow.io', 'framer.app', 'translate.goog',
]);
