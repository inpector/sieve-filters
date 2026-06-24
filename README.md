# Sieve Filters

- [Security and Spam](#security-and-spam)
  - [Filter malicous attachments](#filter-malicous-attachments)
  - [Filter abused standard addresses](#filter-abused-standard-addresses)
  - [RFC-Mandated-Addresses](#rfc-mandated-addresses)
  - [Block common spam tlds](#block-common-spam-tlds)
  - [Block "Dead" addresses](#block-dead-addresses)
  - [Common Spam](#common-spam)
- [Common Security Events](#common-security-events)
- [Sorting Rules](#sorting-rules)
  - [Deliveries](#deliveries)
  - [Finances](#finances)
  - [Fix Costs](#fix-costs)
  - [Free Time](#free-time)
  - [Jobs and Recruting](#jobs-and-recruting)
  - [Shopping](#shopping)
  - [Tech](#tech)
  - [Travelling](#travelling)
- [Special Rules](#special-rules)
  - [Cronjobs & Monitoring](#cronjobs--monitoring)
  - [Mailinglists](#mailinglists)
  - [PDF Bills](#pdf-bills)
- [Last Rule](#last-rule)

## Require for all filters
```yaml
require [
  "body", 
  "comparator-i;ascii-numeric", 
  "copy", 
  "editheader",
  "envelope" , 
  "fileinto" , 
  "imap4flags" , 
  "mailbox", 
  "regex" , 
  "reject", 
  "relational"
];
```

## Security and Spam

### Filter malicous attachments
```yaml
if anyof (
    header :contains "Content-Type" [
        "application/x-msdownload", 
        "application/x-msdos-program", 
        "application/x-dosexec",
        "application/x-msi", 
        "application/x-sh",
        "application/hta",
        "application/x-vbs",
        "application/javascript"
    ],
    
    header :contains ["Content-Type", "Content-Disposition"] [
        ".exe", ".msi", ".com", ".scr", ".pif", ".cpl", ".hta",
        ".bat", ".cmd", ".vbs", ".vbe", ".ps1", 
        ".js", ".jse", ".wsf", ".wsh", ".sh", ".jar"
    ]
) 
{
    reject "Suspicious attachment type blocked for security reasons.";
    stop;
}
```

### Filter abused standard addresses
My private domains do not have such standard addresses - be careful with that filter. Especially i included no-reply here so check if you need any of this localparts.
```yaml
if allof (
    envelope :domain :is "To" [
        "yourdomain.de", 
        "yourdomain.com"
    ],
    
    envelope :localpart :is "To" [ 
        # General & Business Roles
        "admin", "administrator", "billing", "compliance", "contact", 
        "customer", "customerservice", "finance", "help", "helpdesk", 
        "info", "it", "jobs", "management", "marketing", "office", 
        "ops", "orders", "press", "privacy", "sales", "security", 
        "service", "support", "sysadmin", "tech",
        
        # Automated, Network & System Addresses
        "alert", "alerts", "bounce", "bounces", "daemon", "devnull", 
        "dns", "ftp", "infrastructure", "inoc", "ispfeedback", 
        "ispsupport", "list", "list-request", "maildaemon", 
        "mailer-daemon", "no-reply", "noc", "noreply", "notifications", 
        "null", "phish", "phishing", "registrar", "root", "spam", 
        "system", "undisclosed-recipients", "unsubscribe", "updates", 
        "usenet", "uucp", "webmaster", "www"
    ]
) 
{
    discard; 
    stop;
}
```

### RFC-Mandated-Addresses
Let the mandated addresses pass only if they match your domain stack

```yaml
if allof (
    envelope :domain :is "To" [
        "yourdomain.de", 
        "yourdomain.com"
    ],
    envelope :localpart :is "To" [
        "abuse", 
        "postmaster", 
        "hostmaster"
    ]
)
{
    stop;
}
elsif envelope :localpart :is "To" [
        "abuse", 
        "postmaster", 
        "hostmaster"
    ]
{
    discard;
    stop;
} 
```

### Block common spam tlds
This filter is kinda hard... but it helps
```yaml
if address :domain :matches "from" [ 
  "*.ac",
  "*.bond",
  "*.cc",
  "*.cfd",
  "*.click",
  "*.cm",
  "*.cyou",
  "*.date",
  "*.finance",
  "*.gd",
  "*.help",
  "*.icu",
  "*.info",
  "*.li",
  "*.live",
  "*.men",
  "*.online",
  "*.pro",
  "*.ru",
  "*.shop",
  "*.site",
  "*.st",
  "*.support",
  "*.sx",
  "*.top",
  "*.vg",
  "*.win",
  "*.work",
  "*.world",
  "*.ws",
  "*.wtf",
  "*.xin",
  "*.xyz"
] {
    reject "We reject all email servers using certain top-level-domains" ;
    stop ;
}
```

### Block "Dead" addresses
I commonly use CatchAll to give every service its own address. Sometimes the service gets hacked or informations are leaked. Then I change the address and blacklist the localpart here. Edit the reject message to your liking or use discard.
```yaml
if allof(
    envelope :domain :is "To" [
        "yourdomain.de", 
        "yourdomain.com"
    ],
    envelope :localpart :is "To" [ 
      "service1",
      "service2"
    ]
)
{
    reject "I never asked you to send me emails. I ask you to delete my data in accordance with GDPR." ; 
    stop ;
} 
```

### Common Spam
This rule tries to catch any spam passing the above rules. It ads a notice to the mail header so I can find the reason a non-junk Mail is marked as junk and correct the false positives.
```yaml
if anyof ( 

  header :contains "X-Spam-Flag" "YES", 
  header :contains "X-Spam-Level" "*****",
  header :contains "X-MBO-SPAM-Probability" "*****",
  header :value "ge" :comparator "i;ascii-numeric" "X-Spam-Score" "5"
)
{
    addheader "X-Sieve-Filter-Reason" "X-Spam Score";
    addflag "\\Seen";
    fileinto "Junk";
    stop;
}

### DMARC alignment failure
elsif allof (
    anyof (
      header :contains "Authentication-Results" "dmarc=fail",
      header :contains "Authentication-Results" "dmarc=none",
      header :contains "Authentication-Results" "dmarc=permerror"
    ),
    not header :contains "Authentication-Results" "dmarc=pass"
  )
{
    addheader "X-Sieve-Filter-Reason" "DMARC spoofed";
    addflag "\\Seen";
    fileinto "Junk";
    stop;
}
  
### SPF-only failures (no DKIM backup)
elsif allof (
    header :contains "Authentication-Results" "spf=fail",
    not header :contains "Authentication-Results" "dkim=pass"
  )
{
    addheader "X-Sieve-Filter-Reason" "SPF Failure without DMARC";
    addflag "\\Seen";
    fileinto "Junk";
    stop;
}
  
### DKIM-only failures (no SPF backup)
elsif allof (
    header :contains "Authentication-Results" "dkim=fail",
    not header :contains "Authentication-Results" "spf=pass"
  )
{
    addheader "X-Sieve-Filter-Reason" "DKIM failure without SPF";
    addflag "\\Seen";
    fileinto "Junk";
    stop;
}

### Common Phishing patterns

#### Disposable/temporary email providers
elsif address :domain :matches "From" [
    "yopmail.com", "mailinator.com", "guerrillamail.com", 
    "10minutemail.com", "10minutemail.net", "tempmail.com", 
    "tempmailo.com", "tempmail.dev", "getnada.com", "trashmail.com"
  ]
{
    addheader "X-Sieve-Filter-Reason" "Trashmail";
    addflag "\\Seen";
    fileinto "Junk";
    stop;
}
  
#### Typosquatted brand domains (especially payment/banking)
elsif address :domain :matches "From" [
    "*paypal-secure.*", "*paypa[Il].*", "*amaz0n-*.*", "*amazon-order.*",
    "microsoftsecuremail.*", "*micros0ft-*.*", "appleid-verify.*", 
    "icloud-alert.*", "dhl-delivery.*", "fedextrack-*.*", "sparkasse-*.*",
    "*-verifikation.*", "commerzbank-security.*", "postbank-verifikation.*"
  ]
{
    addheader "X-Sieve-Filter-Reason" "Malformed known domains";
    addflag "\\Seen";
    fileinto "Junk";
    stop;
}

#### Phishing subject lines (case-insensitive)
elsif  header :comparator "i;ascii-casemap" :contains "Subject" [
    "verify your account", "update your payment", "unusual login",
    "crypto", "investment opportunity"
  ]
{
    addheader "X-Sieve-Filter-Reason" "Common Phishing Subject";
    addflag "\\Seen";
    fileinto "Junk";
    stop;
}

#### Impersonated support addresses
elsif header :comparator "i;ascii-casemap" :contains "From" [
    "customer support", "security team", "account services"
  ]
{
    addheader "X-Sieve-Filter-Reason" "Impersonated support addresses";
    addflag "\\Seen";
    fileinto "Junk";
    stop;
}

### False Shipping notifications
elsif anyof (
  allof (
     header :contains "Subject" "DHL" , 
     not address :matches :domain "From" [
        "dhl.de", "*.dhl.de",
        "dhl.com", "*.dhl.com",
        "deutschepost.de", "*.deutschepost.de"
    ]
  ),
  allof (
     header :contains "Subject" [
       "Sendung",
       "Paket",
       "Sendungsbenachrichtigung",
       "Geliefert",
       "Versand",
       "DHL",
       "DPD"
     ], 
     not address :domain :matches "From" [
        "dhl.de", "*.dhl.de",
        "dhl.com", "*.dhl.com",
        "deutschepost.de", "*.deutschepost.de",
        "dpd.de", "*.dpd.de",
        "dpd.com", "*.dpd.com",
        "myhermes.de", "*.myhermes.de",
        "hermes-europe.de", "*.hermes-europe.de",
        "ups.com", "*.ups.com",
        "gls-group.eu", "*.gls-group.eu",
        "gls-germany.com", "*.gls-germany.com",
        "fedex.com", "*.fedex.com",
        "tnt.com", "*.tnt.com",
        "post.at", "*.post.at",
        "swisspost.ch", "*.swisspost.ch",
        "amazon.de","*.amazon.de",
        "amazon.com","*.amazon.com"
    ]
  )
)
{
    addheader "X-Sieve-Filter-Reason" "False Notification for shipping";
    addflag "\\Seen";
    fileinto "Junk";
    stop;
}

### RegEX: Suspicious sender patterns from legitimate providers
elsif  allof (
    address :domain :is "From" [
      "gmail.com", "yahoo.com", "yahoo.co.uk", "outlook.com", 
      "hotmail.com", "live.com", "mail.ru", "yandex.ru", "yandex.com",
      "proton.me", "protonmail.com", "zoho.com", "icloud.com"
    ],
    anyof (
      address :localpart :regex "From" "^(noreply|no[-_.]?reply|info|account|support|admin)([-_.]?[0-9]{3,}|[-_.]?[A-Za-z0-9]{6,})$",
      address :localpart :regex "From" "^[A-Za-z0-9]{15,}$",
      address :localpart :regex "From" "^(service|security|update|verify)([-_.]?(notice|alert|center))?[0-9]*$"
    )
  )
{
    addheader "X-Sieve-Filter-Reason" "Suspicious sender patterns";
    addflag "\\Seen";
    fileinto "Junk";
    stop;
}

#### RegEX: Currency symbols (phishing lure tactic)
elsif header :regex "Subject" "[\\$£€]"
{
    addheader "X-Sieve-Filter-Reason" "Currency symbol in subject";
    addflag "\\Seen";
    fileinto "Junk";
    stop;
}

#### RegEX: Invoice patterns with 6+ digits (common phishing template)
elsif header :regex "Subject" "invoice[[:space:]]?#?[0-9]{6,}"
{
    addheader "X-Sieve-Filter-Reason" "subject invoice with digits";
    addflag "\\Seen";
    fileinto "Junk";
    stop;
}
```

## Common Security Events
```yaml
if anyof (
    header :contains "Subject" [
        # English Keywords
        "security alert", "security notification", "security code", 
        "login", "sign in", "sign-in", "sign on", "sign-on", "login attempt",
        "password", "password reset", "email address", "email change", 
        "verification", "one-time password", "otp", "2fa", "mfa", "two-factor", "auth code",
        "new device", "unrecognized device", "unusual activity", "was this you", 
        "account locked", "account recovery","passcode","one-time code",
        
        # German Keywords
        "sicherheitswarnung", "sicherheitscode", "anmelden", "neue anmeldung", 
        "zweistufige anmeldung", "anmeldeversuch", "anmeldecode", 
        "passwort", "passwort zurücksetzen",
        "verifizierungscode", "validierungscode", "bestätigungscode", 
        "einmalpasswort", "einmalcode", "zwei-faktor", 
        "neues gerät", "unbekanntes gerät", "ungewöhnliche aktivität", "waren sie das",
        "konto gesperrt", "kontowiederherstellung","neues Einloggen","anmeldelink"
    ],
    
    address :domain :matches "From" [
        # Original List
        "lastpass.com", "*.lastpass.com", 
        "logme.in", "*.logme.in", 
        "okta.com", "*.okta.com", 
        "accounts.google.com", "*.accounts.google.com", 
        "1password.com", "*.1password.com", 
        "haveibeenpwned.com", "*.haveibeenpwned.com", 
        "nextdns.io", "*.nextdns.io", 
        "bitwarden.com", "*.bitwarden.com"
    ]
) 
{
    fileinto "Security";
    stop;
}

```

## Sorting Rules
For the following rules i split them into a domain matching rule and a keyword rule. The idea is trying to match all the domains first and avoid the false positive matching of keywords. I place the keyword rule after the other domain matching rules.

### Deliveries
```yaml
# Deliveries-Domains
if anyof (
    address :domain :matches "From" [
        "dhl.de", "*.dhl.de",
        "dhl.com", "*.dhl.com",
        "deutschepost.de", "*.deutschepost.de",
        "dpd.de", "*.dpd.de",
        "dpd.com", "*.dpd.com",
        "myhermes.de", "*.myhermes.de",
        "hermes-europe.de", "*.hermes-europe.de",
        "ups.com", "*.ups.com",
        "gls-group.eu", "*.gls-group.eu",
        "gls-germany.com", "*.gls-germany.com",
        "fedex.com", "*.fedex.com",
        "tnt.com", "*.tnt.com",
        "post.at", "*.post.at",
        "swisspost.ch", "*.swisspost.ch" 
    ],
    address :is "From" [
        "shipment-tracking@amazon.de",
        "shipment-tracking@amazon.com",
        "order-update@amazon.de",
        "auto-confirm@amazon.de"
    ],
    allof (
    envelope :domain :is  "To" [
          "yourdomain.de"
      ],
    envelope :localpart :is "To" [ 
        "packstation",
        "hermes",
        "ups",
        "dhl",
        "dpd",
        "fedex"
      ]
    )
)
{
    fileinto "Deliveries"; 
    stop;
}

# Deliveres-Keywords
if header :contains "Subject" [
        # German Keywords
        "sendung", "paket", "sendungsbenachrichtigung", "geliefert", "versand",
        "ist unterwegs", "versandt", "versendet", "zugestellt", "zustellung",
        "lieferung", "sendungsverfolgung", "paketankündigung", "packstation",
        "bestellung", "versandbestätigung", "bestellbestätigung", "ankündigung",
        "verlassen", "abholbereit",

        # English Keywords
        "shipping", "shipped", "delivered", "delivery", "out for delivery",
        "tracking", "dispatch", "dispatched", "package", "order confirmation"
    ]
{
    fileinto "Deliveries"; 
    stop;
}
```
### Finances
```yaml
if address :domain :matches "From" [
    # Traditional Banks (Germany/DACH)
    "ing.de", "*.ing.de",
    "dkb.de", "*.dkb.de",
    "comdirect.de", "*.comdirect.de",
    "sparkasse.de", "*.sparkasse.de",
    "vr.de", "*.vr.de",              
    "postbank.de", "*.postbank.de",
    "consorsbank.de", "*.consorsbank.de",
    "meine-vvb.de","*.meine-vvb.de",
     
    # Modern Fintech, Neobanks & Payment Providers
    "paypal.de", "*.paypal.de",
    "paypal.com", "*.paypal.com",
    "revolut.com", "*.revolut.com",
    "n26.com", "*.n26.com",
    "c24.de", "*.c24.de",
    "klarna.com", "*.klarna.com",
    "zinia.de", "*.zinia.de",
    "curve.com", "*.curve.com",
    "curve.app", "*.curve.app",
    "banknorwegian.de","*.banknorwegian.de",
    "openbankpay.com","*.openbankpay.com",
    
    # Credit Cards & Payment Networks
    "visa.com", "*.visa.com",
    "visa.de", "*.visa.de",
    "mastercard.com", "*.mastercard.com",
    "mastercard.de", "*.mastercard.de",
    "americanexpress.com", "*.americanexpress.com",
    
    # Neo-Brokers & Wealth Management
    "traderepublic.com", "*.traderepublic.com",
    "scalable.capital", "*.scalable.capital",
    "flatex.de", "*.flatex.de",
    "mein-grundeinkommen.de", "*.mein-grundeinkommen.de",
    
    # Credit Bureaus, Taxes & Financial Portals
    "schufa.de", "*.schufa.de",
    "bonify.de", "*.bonify.de",
    "elster.de", "*.elster.de",
    "datev.de", "*.datev.de",
    "datev.com", "*.datev.com",
    "finanzblick.de", "*.finanzblick.de",
    "check24.de", "*.check24.de"
]
{
    fileinto "Finances" ;
    stop ;
}
```
### Fix Costs
```yaml
if address :domain :matches "From" [
    # Telecom & Internet (ISPs)
    "telekom.de", "*.telekom.de",
    "vodafone.de", "*.vodafone.de",
    "vodafone.com", "*.vodafone.com",
    "o2online.de", "*.o2online.de",
    "o2.de", "*.o2.de",
    "1und1.de", "*.1und1.de",
    
    # Energy & Utilities
    "tibber.com", "*.tibber.com",
    "ostrom.de", "*.ostrom.de",
    "maingau-energie.de", "*.maingau-energie.de",
    "enbw.com", "*.enbw.com",
    
    # Mobility, EV Charging & Car
    "hyundai.de", "*.hyundai.de",
    "hyundai.com", "*.hyundai.com",
    "ewego.de", "*.ewego.de", 
    "autoscout24.de", "*.autoscout24.de",
    "mobile.de", "*.mobile.de",
    "adac.de", "*.adac.de",
    
    # Hosting, Domains & Cloud Services
    "uberspace.de", "*.uberspace.de",
    "hetzner.com", "*.hetzner.com",
    "hetzner.de", "*.hetzner.de",
    "strato.de", "*.strato.de",
    "netcup.de", "*.netcup.de",
    "mailbox.org", "*.mailbox.org",
    "ionos.de", "*.ionos.de", 
    
    # Insurances & Healthcare (Krankenkasse)
    "tk.de", "*.tk.de",
    "arag.de", "*.arag.de",
    "cosmosdirekt.de", "*.cosmosdirekt.de",
    "huk.de", "*.huk.de",
    "huk24.de", "*.huk24.de",
    "allianz.de", "*.allianz.de"
]

{
    fileinto "Fixcosts" ;
    stop ;
}

```
### Free Time
```yaml
if anyof (
    # Display Names and Broad Matches (Fediverse, etc.)
    header :contains "From" [
        "Prime Gaming", "Lieferando", "mastodon", ".social"
    ],
    
    # Gaming Platforms & Stores
    address :domain :matches "From" [
        "steampowered.com", "*.steampowered.com",
        "xbox.com", "*.xbox.com",
        "nintendo.net", "*.nintendo.net",
        "nintendo.com", "*.nintendo.com",
        "epicgames.com", "*.epicgames.com",
        "ea.com", "*.ea.com",
        "playstation.com", "*.playstation.com",
        "playstationemail.com", "*.playstationemail.com",
        "rockstargames.com", "*.rockstargames.com",
        "twitch.tv", "*.twitch.tv",
        "ubi.com", "*.ubi.com",
        "blizzard.com", "*.blizzard.com",
        "battle.net", "*.battle.net",
        "bethesda.net", "*.bethesda.net",
        "greenmangaming.com", "*.greenmangaming.com"
    ],
    
    # Social Media
    address :domain :matches "From" [
        "facebook.com", "*.facebook.com",
        "twitter.com", "*.twitter.com",
        "x.com", "*.x.com",
        "instagram.com", "*.instagram.com",
        "pinterest.com", "*.pinterest.com",
        "tumblr.com", "*.tumblr.com",
        "flickr.com", "*.flickr.com",
        "tiktok.com", "*.tiktok.com",
        "reddit.com", "*.reddit.com"
    ],

    # Streaming & Entertainment
    address :domain :matches "From" [
        "netflix.com", "*.netflix.com",
        "youtube.com", "*.youtube.com",
        "spotify.com", "*.spotify.com",
        "plex.tv", "*.plex.tv",
        "crunchyroll.com", "*.crunchyroll.com",
        "wowtv.de", "*.wowtv.de",
        "sky.ch", "*.sky.ch",
        "vimeo.com", "*.vimeo.com",
        "roku.com", "*.roku.com",
        "blinkist.com", "*.blinkist.com",
        "audible.de", "*.audible.de",
        "audible.com", "*.audible.com"
    ],
    allof (
    envelope :domain :is "To" [
          "yourdomain.de"
      ],
    envelope :localpart :is "To" [ 
        "blizzard",
        "facebook",
        "mastodon",
        "spotify",
        "netflix",
        "plex",
        "nintendo",
        "gog",
        "sky"
      ]
    )
) 
{
    fileinto "Freetime";
    stop;
}
```
### Jobs and Recruting
```yaml
if anyof (
    address :domain :matches "From" [
        # Original & General Platforms
        "join.com", "*.join.com",
        "kununu.com", "*.kununu.com",
        "xing.com", "*.xing.com",
        "linkedin.com", "*.linkedin.com",
        "stepstone.de", "*.stepstone.de",
        "stepstone.com", "*.stepstone.com",
        "indeed.com", "*.indeed.com",
        
        # Tech / IT / Freelance Focused (DACH region)
        "get-in-it.de", "*.get-in-it.de",
        "honeypot.io", "*.honeypot.io",
        "talent.io", "*.talent.io",
        "freelancermap.de", "*.freelancermap.de",
        "gulp.de", "*.gulp.de",

        # Common ATS (Applicant Tracking Systems) used by recruiters
        "icims.com", "*.icims.com",
        "personio.de", "*.personio.de",
        "personio.com", "*.personio.com",
        "greenhouse.io", "*.greenhouse.io",
        "lever.co", "*.lever.co",
        "smartrecruiters.com", "*.smartrecruiters.com",
        "workday.com", "*.workday.com",
        "breezy.hr", "*.breezy.hr"
    ],

    header :contains "Subject" [
        # Original Keywords
        "recruiting", "recruiting-nachricht", "jobbenachrichtigung",
        
        # German Additions
        "stellenangebot", "jobangebot", "karrierechance", "karriere", 
        "bewerbung", "vorstellungsgespräch", "neue position", 
        "spannende herausforderung", "headhunter", "bewerbungsprozess",
        "talentsuche", "job-alarm", "job alert",
        
        # English Additions
        "job opportunity", "career opportunity", "talent acquisition", 
        "hiring", "interview", "application status", "new role"
    ]
) 
{
    addflag "\\Seen";
    fileinto "Jobs" ;
    stop ;
}

```
### Shopping
```yaml
if anyof (
    address :domain :matches "From" [
        # Global Marketplaces & Platforms
        "amazon.de", "*.amazon.de",
        "amazon.com", "*.amazon.com",
        "ebay.de", "*.ebay.de",
        "ebay.com", "*.ebay.com",
        "etsy.com", "*.etsy.com",
        "aliexpress.com", "*.aliexpress.com",
        "otto.de","*.otto.de",
        
        # German/DACH Classifieds & Re-commerce
        "kleinanzeigen.de", "*.kleinanzeigen.de",
        "vinted.de", "*.vinted.de",
        "rebuy.de", "*.rebuy.de",
        "momox.de", "*.momox.de",
        "backmarket.de", "*.backmarket.de",
        "toogoodtogo.com","*.toogoodtogo.com",

        # Electronics & IT (DACH)
        "mediamarkt.de", "*.mediamarkt.de",
        "saturn.de", "*.saturn.de",
        "alternate.de", "*.alternate.de",
        "mindfactory.de", "*.mindfactory.de",
        "cyberport.de", "*.cyberport.de",
        "notebooksbilliger.de", "*.notebooksbilliger.de",
        "galaxus.de", "*.galaxus.de",
        
        # Fashion & Lifestyle
        "zalando.de", "*.zalando.de",
        "aboutyou.de", "*.aboutyou.de",
        "hm.com", "*.hm.com",
        "asos.com", "*.asos.com",
        "ansons.de","*.ansons.de",
        
        # Supermarkets, Drugstores & Food Delivery
        "rewe.de", "*.rewe.de",
        "lidl.de", "*.lidl.de",
        "aldi-sued.de", "*.aldi-sued.de",
        "aldi-nord.de", "*.aldi-nord.de",
        "dm.de", "*.dm.de",
        "rossmann.de", "*.rossmann.de",
        "hellofresh.de", "*.hellofresh.de",
        "picnic.app", "*.picnic.app",
        "flink.com", "*.flink.com",
        "getir.com", "*.getir.com",
        "carrefour.fr","*.carrefour.fr",

        # DIY & Furniture
        "ikea.com", "*.ikea.com",
        "ikea.de", "*.ikea.de",
        "obi.de", "*.obi.de",
        "hornbach.de", "*.hornbach.de",
        "bauhaus.info", "*.bauhaus.info",
        "toom.de", "*.toom.de",
        "home24.de", "*.home24.de",
        "wayfair.de", "*.wayfair.de",

        # Payback and other cashbacks
        "shoop.de", "*.shoop.de"
    ]
)
{
    fileinto "Shopping"; 
    stop;
}
if header :contains "Subject" [
        # German Keywords
        "bestellung", "bestellbestätigung", "rechnung", "zahlung", 
        "abbuchungsankündigung", "beleg", "quittung", "kaufbestätigung", 
        "vielen dank für ihren einkauf", "auftragsbestätigung", "kaufabwicklung",
        
        # English Keywords
        "order", "order confirmation", "invoice", "receipt", "payment", 
        "thank you for your purchase", "purchase confirmation"
    ]
{
    fileinto "Shopping"; 
    stop;
}
```
### Tech
```yaml
if address :domain :matches "From" [
    # Developer, Cloud, and Homelab Infrastructure
    "digitalocean.com", "*.digitalocean.com",
    "github.com", "*.github.com",
    "cloudflare.com", "*.cloudflare.com",
    "docker.com", "*.docker.com",
    "heroku.com", "*.heroku.com",
    "namecheap.com", "*.namecheap.com",
    "keybase.io", "*.keybase.io",

    # Big Tech, Software & Hardware Ecosystems
    "google.com", "*.google.com",
    "apple.com", "*.apple.com",
    "microsoft.com", "*.microsoft.com",
    "meta.com", "*.meta.com",
    "adobe.com", "*.adobe.com",
    "logitech.com", "*.logitech.com",
    "samsung.com", "*.samsung.com",
    "samsung.de", "*.samsung.de"
]
{
    fileinto "Tech";
    stop;
}
```
### Travelling
```yaml
if anyof (
    address :domain :matches "From" [
        "bahn.de", "*.bahn.de",            
        "lufthansa.com", "*.lufthansa.com",
        "ryanair.com", "*.ryanair.com",
        "booking.com", "*.booking.com",
        "airbnb.com", "*.airbnb.com",
        "expedia.de", "*.expedia.de",
        "hotels.com", "*.hotels.com",
        "flixbus.de", "*.flixbus.de",
        "flixbus.com", "*.flixbus.com",
        
        "uber.com", "*.uber.com",
        "bolt.eu", "*.bolt.eu",
        "miles-mobility.com", "*.miles-mobility.com",
        "tier.app", "*.tier.app",
        "sharenow.com", "*.sharenow.com",

        "hahn-airport.de","*.hahn-airport.de"
    ]
)
{
    fileinto "Travel";
    stop;
}

if  header :contains "Subject" [
        "buchungsbestätigung", "reiseplan", "boarding pass", "bordkarte",
        "ticket", "hotelreservierung", "flight itinerary", "reservation",
        "check-in", "zugbindung", "fahrkarte"
    ]
{
    fileinto "travelling";
    stop;
}
```

## Special Rules
These rules maybe needed to place before the sorting rules to avoid false positives.

### Cronjobs & Monitoring
```yaml
if anyof (
    address :domain :matches "From" [
        "uptimerobot.com", "*.uptimerobot.com",
        "healthchecks.io", "*.healthchecks.io",
        "sentry.io", "*.sentry.io",
        "datadoghq.com", "*.datadoghq.com",
        "grafana.net", "*.grafana.net"
    ],

    header :contains "From" [
      "Cron"
    ],
    header :contains "Subject" [
        "cron daemon", "cron <", "letsencrypt expiry", 
        "let's encrypt certificate expiration", "fail2ban", 
        "smartd", "monit alert", "backup successful", "backup failed",
        "server alert", "uptime alert"
    ]
)
{
    fileinto "Monitoring" ;
    stop ;
}
```
### Mailinglists
```yaml
if anyof (
    exists ["List-Unsubscribe", "List-Unsubscribe-Post"],
    header :contains "Precedence" ["bulk", "list", "junk"],
    exists ["List-Id", "X-BeenThere", "X-Mailinglist", "X-Mailing-List"],
    header :contains ["To", "Cc"] ["@lists.", "newsletter@"]
) 
{
    fileinto "mailinglists" ;
    stop ;
}
```

For specific lists I match the list-id parameter or if its absend the lists. Domain
```yaml
if header :contains "List-Id" "denog.lists.denog.de" 
{
    fileinto "mailinglists/Denog" ;
    stop ;
}
elsif header :contains ["To", "Cc"] "@lists.hacksaar.de" 
{
    fileinto "mailinglists/Hacksaar" ;
    stop ;
}
```
### PDF Bills
Copies bills to a seperate folder - useful for parsing them in a external tool like paperless-ngx
```yaml
if allof (
    body :raw :contains "application/pdf",
    
    anyof (
        # Check the Subject
        header :contains "Subject" [
            "rechnung", "invoice", "quittung", "receipt", 
            "zahlungsbestätigung", "abrechnung", "bestellbestätigung", 
            "payment confirmation", "billing", "your bill"
        ],
        body :text :contains [
            "rechnung anbei", "attached invoice", "im anhang erhalten sie", 
            "betrag von", "total amount", "rechnungsbetrag", "rechnungsnummer"
        ]
    )
)
{
    fileinto :copy "bills";
}
```

## Last Rule
Matching (not) my own email addresses
```yaml
if address :matches ["To", "Cc"] [
    "mail@domain.de", 
    "othermail@domain.com
] 
{
    addflag "\\seen";
}

if not address :matches ["To", "Cc"] [
    "mail@domain.de", 
    "othermail@domain.com
] 
{
    fileinto "CatchAll";
    stop;
}
```