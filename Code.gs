/**
 * Gmail Add-on for Phishing Email Detection
 * Main entry point and UI functions
 */

// Phishing detection heuristics
const URGENCY_WORDS = [
  'urgent', 'immediately', 'action required', 'verify now', 'password', 'suspend', 'limited time'
];

const SUSPICIOUS_TLDS = [
  'zip', 'mov', 'click', 'country', 'gq', 'tk', 'ml'
];

/**
 * Creates a card that displays phishing analysis results
 */
function createPhishingAnalysisCard() {
  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle('Phishing Detector')
      .setSubtitle('Analyzing current email...'))
    .addSection(createAnalysisSection())
    .build();
  
  return card;
}

/**
 * Creates the main analysis section
 */
function createAnalysisSection() {
  const section = CardService.newCardSection()
    .setHeader('Email Analysis');
  
  // Get current email
  const email = getCurrentEmail();
  if (!email) {
    section.addWidget(CardService.newTextParagraph()
      .setText('No email selected or unable to access email content.'));
    return section;
  }
  
  // Analyze email
  const result = detectPhishing(email.subject, email.from, email.body);
  
  // Display results
  section.addWidget(CardService.newTextParagraph()
    .setText(`<b>Risk Score: ${result.score}/100</b>`));
  
  if (result.reasons.length > 0) {
    section.addWidget(CardService.newTextParagraph()
      .setText('<b>Detected Issues:</b>'));
    
    result.reasons.forEach(reason => {
      section.addWidget(CardService.newTextParagraph()
        .setText(`• ${reason}`));
    });
  } else {
    section.addWidget(CardService.newTextParagraph()
      .setText('No suspicious patterns detected.'));
  }
  
  // Add refresh button
  section.addWidget(CardService.newTextButton()
    .setText('Refresh Analysis')
    .setOnClickAction(CardService.newAction()
      .setFunctionName('createPhishingAnalysisCard')));
  
  return section;
}

/**
 * Gets the current email being viewed
 */
function getCurrentEmail() {
  try {
    const accessToken = ScriptApp.getOAuthToken();
    const messageId = GmailApp.getCurrentMessageId();
    
    if (!messageId) {
      return null;
    }
    
    const message = GmailApp.getMessageById(messageId);
    if (!message) {
      return null;
    }
    
    return {
      subject: message.getSubject() || '',
      from: message.getFrom() || '',
      body: message.getPlainBody() || ''
    };
  } catch (error) {
    console.error('Error getting email:', error);
    return null;
  }
}

/**
 * Detects phishing patterns in email content
 */
function detectPhishing(subject, fromEmail, bodyText) {
  let score = 0;
  const reasons = [];
  
  const senderDomain = getDomain(fromEmail) || '';
  const lower = (subject + ' ' + bodyText).toLowerCase();
  
  // Check for urgency words
  for (const word of URGENCY_WORDS) {
    if (lower.includes(word)) {
      score += 10;
      reasons.push(`Detected urgency phrase: "${word}"`);
      break;
    }
  }
  
  // Check for suspicious links
  const domains = extractDomainsFromText(bodyText);
  for (const domain of domains) {
    if (hasSuspiciousTld(domain)) {
      score += 10;
      reasons.push(`Link uses suspicious TLD: ${domain}`);
    }
    const linkRoot = getDomain(domain) || domain;
    if (senderDomain && linkRoot !== senderDomain) {
      score += 8;
      reasons.push(`Sender domain (${senderDomain}) differs from link domain (${linkRoot})`);
    }
  }
  
  // Check for suspicious sender patterns
  if (fromEmail && fromEmail.includes('@')) {
    const nameLike = fromEmail.split('@')[0];
    if (/\d{3,}/.test(nameLike)) {
      score += 5;
      reasons.push('Sender local-part contains many digits (possible throwaway account)');
    }
  }
  
  // Check for non-ASCII characters (potential homoglyphs)
  if (/[^\u0000-\u007F]/.test(subject) || /[^\u0000-\u007F]/.test(bodyText)) {
    score += 4;
    reasons.push('Subject or body contains non-ASCII characters that may be homoglyphs');
  }
  
  // Cap score at 100
  if (score > 100) score = 100;
  
  return { score, reasons };
}

/**
 * Extracts domains from text content
 */
function extractDomainsFromText(text) {
  const urlRegex = /(https?:\/\/)?([\w-]+\.)+[\w-]+/gi;
  const domains = new Set();
  
  let match;
  while ((match = urlRegex.exec(text)) !== null) {
    const full = match[0];
    try {
      const url = full.startsWith('http') ? new URL(full) : new URL('https://' + full);
      domains.add(url.hostname.toLowerCase());
    } catch (e) {
      // Ignore invalid URLs
    }
  }
  
  return Array.from(domains);
}

/**
 * Gets the root domain from an email or hostname
 */
function getDomain(emailOrHost) {
  const atIdx = emailOrHost.indexOf('@');
  const host = atIdx >= 0 ? emailOrHost.slice(atIdx + 1) : emailOrHost;
  const parts = host.toLowerCase().split('.');
  if (parts.length < 2) return host;
  return parts.slice(-2).join('.');
}

/**
 * Checks if a hostname has a suspicious TLD
 */
function hasSuspiciousTld(hostname) {
  const parts = hostname.toLowerCase().split('.');
  const tld = parts[parts.length - 1];
  return SUSPICIOUS_TLDS.includes(tld);
}

/**
 * Required function for Gmail Add-ons
 */
function onGmailMessage(e) {
  return createPhishingAnalysisCard();
}

/**
 * Required function for Gmail Add-ons
 */
function onGmailCompose(e) {
  return createPhishingAnalysisCard();
}
