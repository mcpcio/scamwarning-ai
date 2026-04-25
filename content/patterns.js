const SCAM_PATTERNS = {
  urgency: [
    /\b(act now|limited time|expires? today|only \d+ left)\b/gi,
    /\b(don'?t miss|last chance|hurry|immediate action required)\b/gi,
    /your account (has been|will be) (suspended|closed|locked|terminated|deactivated)/gi,
    /\b(deadline|urgent|time.?sensitive|final notice|final warning)\b/gi,
    /\b(offer expires|sale ends|countdown|hours? left|minutes? left)\b/gi,
    /\b(act fast|limited spots?|selling out|almost gone)\b/gi
  ],
  phishing: [
    /verify your (account|identity|password|payment|email|information)/gi,
    /confirm your (billing|credit card|bank|SSN|social security|identity)/gi,
    /unusual (activity|sign.?in|login|transaction) (detected|noticed|found)/gi,
    /\b(update your payment|payment failed|billing issue|payment declined)\b/gi,
    /\b(sign.?in to (confirm|verify|update|secure))\b/gi,
    /\b(click here to (verify|confirm|secure|unlock|restore))\b/gi,
    /\b(your.{0,10}password.{0,10}(expired|reset|changed|compromised))\b/gi
  ],
  financial_fraud: [
    /guaranteed (returns?|profit|income|earnings|results)/gi,
    /risk.?free (investment|trading|opportunity|returns)/gi,
    /(double|triple|10x|100x) your (money|investment|bitcoin|crypto)/gi,
    /secret (method|strategy|system|formula).{0,30}(rich|wealth|million|passive income)/gi,
    /\b(forex|crypto|bitcoin).{0,20}(guaranteed|risk.?free|no.?loss)/gi,
    /\b(make \$?\d+[,.]?\d*k?.{0,10}(per|a|each) (day|week|month|hour))\b/gi,
    /\b(financial freedom|quit your job|passive income).{0,30}(secret|method|system|course)\b/gi,
    /\b(wire transfer|western union|money.?gram|gift card).{0,20}(send|pay|transfer)\b/gi
  ],
  tech_support: [
    /your (computer|device|system|pc|mac) (is|has been) (infected|compromised|hacked|at risk)/gi,
    /call (now|immediately|this number|us).{0,30}(support|helpline|tech|microsoft|apple)/gi,
    /(microsoft|apple|google|windows|norton|mcafee).{0,20}(detected|found|blocked).{0,20}(virus|malware|threat|trojan)/gi,
    /\b(virus detected|malware found|trojan detected|security alert|critical warning)\b/gi,
    /\b(your firewall|your antivirus).{0,20}(expired|disabled|outdated|compromised)\b/gi,
    /\b(call \+?1?.?\(?\d{3}\)?.?\d{3}.?\d{4})\b/gi
  ],
  too_good: [
    /you('ve| have) (won|been selected|been chosen|qualified for)/gi,
    /(free|claim|win) .{0,20}(iphone|ipad|macbook|samsung|gift card|prize|reward)/gi,
    /congratulations.{0,30}(winner|selected|lucky|chosen|visitor)/gi,
    /unclaimed (funds|inheritance|prize|reward|package|lottery)/gi,
    /\b(lottery|sweepstakes|giveaway).{0,20}(winner|won|claim|congratulations)\b/gi,
    /\b(million|billion) (dollar|pound|euro).{0,20}(inheritance|fund|grant|donation)\b/gi,
    /\b(nigerian|foreign|overseas).{0,20}(prince|royalty|minister|diplomat|fund)\b/gi
  ],
  data_harvest: [
    /enter your (SSN|social security|credit card|bank account|routing number|tax.?id)/gi,
    /\b(provide|submit|enter).{0,15}(full name|date of birth|mother'?s maiden|passport)\b/gi,
    /\b(we need your|please provide your|confirm your).{0,20}(personal|financial|banking) (information|details|data)\b/gi
  ],
  misleading_ads: [
    /\b(doctors? (hate|don'?t want you)|one weird trick|this one thing)\b/gi,
    /\b(shocking|jaw.?dropping|unbelievable) (truth|secret|discovery|result)\b/gi,
    /\b(before and after|miracle|breakthrough|revolutionary).{0,20}(weight|diet|cure|treatment|supplement)\b/gi,
    /\b(celebrities?|stars?) (use|endorse|recommend|swear by)\b/gi,
    /\b(FDA|government|big pharma).{0,20}(doesn'?t want|hiding|banned|secret)\b/gi
  ],
  suspicious_commerce: [
    /\b(90|95|99)% off\b/gi,
    /\b(going out of business|clearance|liquidation).{0,20}(everything must go|final sale)\b/gi,
    /\b(no refund|all sales final|non.?refundable)\b/gi
  ]
};

const SIGNAL_WEIGHTS = {
  urgency: 1.0,
  phishing: 3.0,
  financial_fraud: 2.5,
  tech_support: 2.5,
  too_good: 2.0,
  data_harvest: 3.0,
  misleading_ads: 1.0,
  suspicious_commerce: 0.5
};
