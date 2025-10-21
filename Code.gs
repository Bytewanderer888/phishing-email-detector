// Gmail Add-on for Phishing Email Detection
// Advanced Free AI-like Detection (No External API Required)
// Uses: NLP, Bayesian Scoring, Pattern Recognition

// ============ CONFIGURATION AREA ============

// Urgency patterns & weights
const URGENCY_PATTERNS = {
  critical: { words: ['urgent', 'immediately', 'action required', 'act now'], weight: 12 },
  account:  { words: ['verify', 'confirm', 'suspend', 'locked', 'expire'],       weight: 10 },
  financial:{ words: ['payment', 'refund', 'invoice', 'transaction', 'billing'], weight: 8  },
  security: { words: ['security alert', 'unusual activity', 'suspicious', 'compromised'], weight: 11 }
};

// Suspicious TLDs
const SUSPICIOUS_TLDS = ['zip','mov','click','country','gq','tk','ml','cf','ga','xyz'];

// Trusted domains
const TRUSTED_DOMAINS = [
  'google.com','gmail.com','microsoft.com','apple.com','amazon.com',
  'paypal.com','facebook.com','linkedin.com','twitter.com','instagram.com'
];

// Common brand keywords (for spoof-detection)
const BRAND_KEYWORDS = [
  'paypal','amazon','google','microsoft','apple','bank','netflix',
  'ebay','facebook','instagram','dhl','fedex','ups'
];

// ============ GMAIL ADD-ON REQUIRED FUNCTIONS ============

/**
 * Homepage trigger – shows main interface in Gmail sidebar.
 */
function onHomepage(e) {
  return createPhishingAnalysisCard();
}

/**
 * Context trigger – fires when user opens a message.
 */
function onGmailMessageOpen(e) {
  try {
    var accessToken = e.gmail.accessToken;
    GmailApp.setCurrentMessageAccessToken(accessToken);
    const messageId = e.gmail.messageId;
    const message   = GmailApp.getMessageById(messageId);
    if (!message) {
      return createErrorCard('Unable to locate the specified email.');
    }

    const email = {
      subject: message.getSubject()   || 'No Subject',
      from:    message.getFrom()      || 'Unknown Sender',
      body:    message.getPlainBody() || '',
      date:    message.getDate()      || new Date()
    };

    return createPhishingAnalysisCard(email);
  } catch (error) {
    console.error('Error accessing email:', error);
    return createErrorCard('Could not access the email content. Error: ' + error.toString());
  }
}

/**
 * Trigger when composing email.
 */
function onGmailCompose(e) {
  return createComposeAnalysisCard();
}

// ============ UI FUNCTIONS ============

function createPhishingAnalysisCard(emailData = null) {
  const cardBuilder = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle('🛡️ Phishing Detector')
      .setSubtitle('Advanced ML-Powered Analysis'));

  if (!emailData) {
    const section = CardService.newCardSection()
      .addWidget(CardService.newTextParagraph()
        .setText('📧 Please open an email to perform analysis.'))
      .addWidget(CardService.newTextParagraph()
        .setText('When you open an email, the add-on will automatically analyze its safety.'));
    cardBuilder.addSection(section);
  } else {
    const analysisSection = createAnalysisSection(emailData);
    cardBuilder.addSection(analysisSection);
  }

  return cardBuilder.build();
}

function createComposeAnalysisCard() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle('🛡️ Phishing Detector')
      .setSubtitle('Compose-Time Safety Check'))
    .addSection(
      CardService.newCardSection()
        .addWidget(CardService.newTextParagraph()
          .setText('When composing an email, make sure to:'))
        .addWidget(CardService.newTextParagraph()
          .setText('• Avoid including sensitive information'))
        .addWidget(CardService.newTextParagraph()
          .setText('• Be cautious with attachments'))
        .addWidget(CardService.newTextParagraph()
          .setText('• Verify recipients’ addresses'))
    )
    .build();
}

function createAnalysisSection(email) {
  const section = CardService.newCardSection()
    .setHeader('📊 Intelligent Email Analysis');

  section.addWidget(CardService.newTextParagraph()
    .setText(`<b>📨 From:</b> ${email.from}`));
  section.addWidget(CardService.newTextParagraph()
    .setText(`<b>📝 Subject:</b> ${email.subject}`));

  const result    = intelligentPhishingDetection(email.subject, email.from, email.body);
  const riskLevel = getRiskLevel(result.score);

  section.addWidget(CardService.newTextParagraph()
    .setText(`<br><b><font color="${riskLevel.color}">🎯 Risk Score: ${result.score}/100</font></b><br>` +
             `<b>Threat Level: ${riskLevel.label}</b><br>` +
             `<b>Confidence: ${result.confidence}%</b>`));

  if (result.threats.length > 0) {
    section.addWidget(CardService.newTextParagraph()
      .setText('<br><b>🚨 Detected Threats:</b>'));
    result.threats.forEach(threat => {
      section.addWidget(CardService.newTextParagraph()
        .setText(`${threat.icon} <b>${threat.category}:</b> ${threat.description}`));
    });
  } else {
    section.addWidget(CardService.newTextParagraph()
      .setText('<br>✅ No significant threats detected.'));
  }

  if (result.analysis.length > 0) {
    section.addWidget(CardService.newTextParagraph()
      .setText('<br><b>🔍 Detailed Analysis:</b>'));
    result.analysis.forEach(item => {
      section.addWidget(CardService.newTextParagraph()
        .setText(`• ${item}`));
    });
  }

  if (result.score >= 40) {
    const recommendations = generateRecommendations(result.score);
    section.addWidget(CardService.newTextParagraph()
      .setText(`<br><b>💡 Safety Recommendations:</b><br>${recommendations.join('<br>')}`));
  }

  // Add interactive buttons directly into the section
  section.addWidget(CardService.newTextButton()
    .setText('🔄 Re-Analyze')
    .setOnClickAction(CardService.newAction()
      .setFunctionName('onHomepage')));

  if (result.score >= 60) {
    section.addWidget(CardService.newTextButton()
      .setText('🔒 Security Tips')
      .setOnClickAction(CardService.newAction()
        .setFunctionName('showSecurityTips')));
  }

  return section;
}

function createErrorCard(errorMessage) {
  const cardBuilder = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle('🛡️ Phishing Detector')
      .setSubtitle('Analysis Error'));

  const section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph()
      .setText('❌ ' + errorMessage))
    .addWidget(CardService.newTextParagraph()
      .setText('Please ensure:'))
    .addWidget(CardService.newTextParagraph()
      .setText('• All required permissions are granted'))
    .addWidget(CardService.newTextParagraph()
      .setText('• You are viewing a valid email message'))
    .addWidget(CardService.newTextButton()
      .setText('🔄 Retry')
      .setOnClickAction(CardService.newAction()
        .setFunctionName('onHomepage')));

  cardBuilder.addSection(section);
  return cardBuilder.build();
}

// ============ CORE INTELLIGENT DETECTION ENGINE ============

function intelligentPhishingDetection(subject, fromEmail, bodyText) {
  const threats     = [];
  const analysis    = [];
  let totalScore    = 0;
  let maxConfidence = 0;

  // Pre-processing
  const lowerText    = (subject + ' ' + bodyText).toLowerCase();
  const senderDomain = getDomain(fromEmail);

  // 1. NLP text-feature analysis
  const nlpResult = nlpTextAnalysis(subject, bodyText);
  totalScore       += nlpResult.score;
  threats.push(...nlpResult.threats);
  analysis.push(...nlpResult.insights);
  maxConfidence    = Math.max(maxConfidence, nlpResult.confidence);

  // 2. Bayesian scoring system
  const bayesResult = bayesianScoring(lowerText, senderDomain);
  totalScore        += bayesResult.score;
  threats.push(...bayesResult.threats);
  analysis.push(...bayesResult.insights);
  maxConfidence     = Math.max(maxConfidence, bayesResult.confidence);

  // 3. Advanced heuristic detection
  const heuristicResult = advancedHeuristicDetection(subject, fromEmail, bodyText);
  totalScore            += heuristicResult.score;
  threats.push(...heuristicResult.threats);
  analysis.push(...heuristicResult.insights);
  maxConfidence         = Math.max(maxConfidence, heuristicResult.confidence);

  // 4. URL deep analysis
  const urlResult = deepUrlAnalysis(bodyText, senderDomain);
  totalScore    += urlResult.score;
  threats.push(...urlResult.threats);
  analysis.push(...urlResult.insights);
  maxConfidence = Math.max(maxConfidence, urlResult.confidence);

  // 5. Brand-spoofing detection
  const spoofingResult = brandSpoofingDetection(fromEmail, lowerText);
  totalScore           += spoofingResult.score;
  threats.push(...spoofingResult.threats);
  analysis.push(...spoofingResult.insights);
  maxConfidence        = Math.max(maxConfidence, spoofingResult.confidence);

  // Normalize score to max 100
  const finalScore     = Math.min(Math.round(totalScore), 100);
  const avgConfidence  = Math.round(maxConfidence);

  return {
    score:      finalScore,
    confidence: avgConfidence,
    threats:    threats,
    analysis:   analysis
  };
}

// ============ 1. NLP Text-Feature Analysis ============

function nlpTextAnalysis(subject, bodyText) {
  let score     = 0;
  const threats = [];
  const insights= [];
  let confidence= 0;

  const text       = subject + ' ' + bodyText;
  const lowerText  = text.toLowerCase();
  const words      = lowerText.match(/\b\w+\b/g) || [];
  const wordCount  = words.length;

  // Urgency language detection
  let urgencyScore = 0;
  let urgencyCount = 0;
  Object.keys(URGENCY_PATTERNS).forEach(category => {
    URGENCY_PATTERNS[category].words.forEach(word => {
      const regex = new RegExp('\\b' + word + '\\b', 'gi');
      const matches= lowerText.match(regex);
      if (matches) {
        urgencyCount += matches.length;
        urgencyScore += matches.length * URGENCY_PATTERNS[category].weight;
      }
    });
  });
  if (urgencyCount > 0) {
    score      += Math.min(urgencyScore, 30);
    confidence  = Math.min((urgencyCount / Math.max(wordCount,1) * 100) * 10, 85);
    threats.push({
      icon:        '⚠️',
      category:    'Urgency Language Manipulation',
      description: `Detected ${urgencyCount} high-pressure phrases`
    });
    insights.push(`High-pressure language ratio: ${(urgencyCount / Math.max(wordCount,1) * 100).toFixed(1)}%`);
  }

  // Sentence length analysis
  const sentences       = text.split(/[.!?]+/).filter(s => s.trim().length > 0);
  const avgSentenceLen  = wordCount / (sentences.length || 1);
  if (avgSentenceLen < 8 && sentences.length > 3) {
    score     += 8;
    insights.push('Detected unusually short sentence structure (common in phishing)');
  }

  // Excessive uppercase letters
  const upperCaseRatio = (text.match(/[A-Z]/g) || []).length / Math.max(text.length,1);
  if (upperCaseRatio > 0.3 && text.length > 50) {
    score     += 10;
    confidence = Math.max(confidence, 70);
    threats.push({
      icon:        '📢',
      category:    'Aggressive Format',
      description: 'Excessive uppercase letters (shouting style)'
    });
  }

  // Non-ASCII characters (potential homoglyph attack)
  const nonAsciiCount = (text.match(/[^\x00-\x7F]/g) || []).length;
  if (nonAsciiCount > 5) {
    score     += 12;
    confidence = Math.max(confidence, 75);
    threats.push({
      icon:        '🔤',
      category:    'Homoglyph Attack',
      description: `Detected ${nonAsciiCount} non-ASCII characters (possible spoofing)`
    });
  }

  return { score: score, threats: threats, insights: insights, confidence: confidence };
}

// ============ 2. Bayesian Scoring System ============

function bayesianScoring(lowerText, senderDomain) {
  let score     = 0;
  const threats = [];
  const insights= [];
  let confidence= 0;

  // Prior probability based on domain reputation
  let priorProbPhishing = 0.5;
  if (TRUSTED_DOMAINS.some(domain => senderDomain.includes(domain))) {
    priorProbPhishing = 0.1;
    insights.push(`Sender domain is trusted: ${senderDomain}`);
  } else if (senderDomain.length < 6 || senderDomain.split('.').length > 3) {
    priorProbPhishing = 0.7;
  }

  // Features
  const features = {
    hasUrgency:     URGENCY_PATTERNS.critical.words.some(w => lowerText.includes(w)),
    hasFinancial:   URGENCY_PATTERNS.financial.words.some(w => lowerText.includes(w)),
    hasVerification:/verify|confirm|update.*account/i.test(lowerText),
    hasLinks:       /https?:\/\//gi.test(lowerText),
    hasAttachment:  /attachment|attached|download/i.test(lowerText)
  };

  // Bayesian update
  let posteriorProb = priorProbPhishing;
  if (features.hasUrgency) {
    posteriorProb = updateBayesian(posteriorProb, 0.8, 0.2);
  }
  if (features.hasFinancial && features.hasVerification) {
    posteriorProb = updateBayesian(posteriorProb, 0.85, 0.15);
    threats.push({
      icon: '💰',
      category: 'Financial + Verification Combo',
      description: 'Suspicious combination of finance terms and account verification request'
    });
  }
  if (features.hasLinks && features.hasUrgency) {
    posteriorProb = updateBayesian(posteriorProb, 0.75, 0.25);
  }

  score      = Math.round(posteriorProb * 40);
  confidence = Math.round(posteriorProb * 100);
  insights.push(`Bayesian phishing probability: ${(posteriorProb * 100).toFixed(1)}%`);

  return { score: score, threats: threats, insights: insights, confidence: confidence };
}

function updateBayesian(priorProb, truePositiveRate, falsePositiveRate) {
  const evidence = (truePositiveRate * priorProb) + (falsePositiveRate * (1 - priorProb));
  return (truePositiveRate * priorProb) / evidence;
}

// ============ 3. Advanced Heuristic Detection ============

function advancedHeuristicDetection(subject, fromEmail, bodyText) {
  let score         = 0;
  const threats     = [];
  const insights    = [];
  let confidence    = 0;

  const senderAnalysis  = analyzeSender(fromEmail);
  score               += senderAnalysis.score;
  threats.push(...senderAnalysis.threats);
  insights.push(...senderAnalysis.insights);
  confidence          = Math.max(confidence, senderAnalysis.confidence);

  const subjectAnalysis = analyzeSubject(subject);
  score                += subjectAnalysis.score;
  threats.push(...subjectAnalysis.threats);
  insights.push(...subjectAnalysis.insights);
  confidence           = Math.max(confidence, subjectAnalysis.confidence);

  const bodyAnalysis    = analyzeBodyStructure(bodyText);
  score               += bodyAnalysis.score;
  threats.push(...bodyAnalysis.threats);
  insights.push(...bodyAnalysis.insights);
  confidence           = Math.max(confidence, bodyAnalysis.confidence);

  return { score: score, threats: threats, insights: insights, confidence: confidence };
}

function analyzeSender(fromEmail) {
  let score       = 0;
  const threats   = [];
  const insights  = [];
  let confidence  = 0;

  if (!fromEmail || !fromEmail.includes('@')) {
    return { score: 0, threats: [], insights: [], confidence: 0 };
  }
  const parts     = fromEmail.split('@');
  const localPart = parts[0].toLowerCase();
  const domain    = parts[1].toLowerCase();

  if (/\d{5,}/.test(localPart)) {
    score       += 15;
    confidence   = 80;
    threats.push({
      icon:        '👤',
      category:    'Suspicious Sender',
      description: 'Email address contains multiple consecutive digits (likely automated/throw-away account)'
    });
  }
  if (/[a-z0-9]{15,}/i.test(localPart) && !/[aeiou]{2}/i.test(localPart)) {
    score       += 12;
    confidence   = Math.max(confidence, 75);
    insights.push('Sender address appears randomly generated');
  }
  if (domain.split('.').length > 3) {
    score       += 8;
    insights.push('Sender domain has unusual subdomain structure');
  }

  return { score: score, threats: threats, insights: insights, confidence: confidence };
}

function analyzeSubject(subject) {
  let score       = 0;
  const threats   = [];
  const insights  = [];
  let confidence  = 0;

  if (!subject || subject.length === 0) {
    score       += 10;
    threats.push({
      icon:        '📭',
      category:    'Missing Subject',
      description: 'Email has no subject line (common phishing tactic)'
    });
    return { score: score, threats: threats, insights: insights, confidence: confidence };
  }

  const lower = subject.toLowerCase();
  if (/^(re|fwd):/i.test(subject)) {
    score       += 8;
    confidence   = 65;
    insights.push('Subject uses reply/forward prefix (possible social engineering)');
  }
  const punctuationRatio = (subject.match(/[!?]{2,}/g) || []).length;
  if (punctuationRatio > 0) {
    score       += 7;
    threats.push({
      icon:        '‼️',
      category:    'Excessive Punctuation',
      description: 'Multiple exclamation/question marks (urgency manipulation)'
    });
  }

  return { score: score, threats: threats, insights: insights, confidence: confidence };
}

function analyzeBodyStructure(bodyText) {
  let score       = 0;
  const threats   = [];
  const insights  = [];
  let confidence  = 0;

  if (!bodyText || bodyText.trim().length < 10) {
    return { score: 0, threats: threats, insights: insights, confidence: confidence };
  }

  const linkMatches    = bodyText.match(/https?:\/\//gi) || [];
  const linkDensity    = linkMatches.length / (bodyText.length / 100 || 1);
  if (linkDensity > 5) {
    score       += 15;
    confidence   = 80;
    threats.push({
      icon:        '🔗',
      category:    'High Link Density',
      description: `Unusually many links (found ${linkMatches.length} links in short text)`
    });
  }

  const excessiveSpaces = (bodyText.match(/\s{10,}/g) || []).length;
  if (excessiveSpaces > 2) {
    score       += 10;
    insights.push('Detected potential hidden text or formatting trick (excessive spaces)');
  }

  const htmlTagCount    = (bodyText.match(/<[^>]+>/g) || []).length;
  if (htmlTagCount > 20 && bodyText.length < 500) {
    score       += 8;
    insights.push('High HTML‐to‐text ratio (potential disguise)');
  }

  return { score: score, threats: threats, insights: insights, confidence: confidence };
}

// ============ 4. URL Deep Analysis ============

function deepUrlAnalysis(bodyText, senderDomain) {
  let score       = 0;
  const threats   = [];
  const insights  = [];
  let confidence  = 0;

  const domains = extractDomainsFromText(bodyText);
  if (domains.length === 0) {
    return { score: score, threats: threats, insights: insights, confidence: confidence };
  }

  insights.push(`Detected ${domains.length} unique domain(s) in email body`);
  domains.forEach(domain => {
    if (hasSuspiciousTld(domain)) {
      score     += 12;
      confidence = Math.max(confidence, 85);
      threats.push({
        icon:        '🌐',
        category:    'Suspicious TLD',
        description: `Domain uses high-risk TLD: ${domain}`
      });
    }
    const linkRoot = getDomain(domain);
    if (senderDomain && linkRoot !== senderDomain && !domain.includes(senderDomain)) {
      score       += 10;
      confidence   = Math.max(confidence, 70);
      threats.push({
        icon:        '⚠️',
        category:    'Domain Mismatch',
        description: `Link domain (${linkRoot}) differs from sender domain (${senderDomain})`
      });
    }
    const obfuscationScore = detectUrlObfuscation(domain);
    if (obfuscationScore > 0) {
      score       += obfuscationScore;
      confidence   = Math.max(confidence, 80);
      threats.push({
        icon:        '🎭',
        category:    'URL Obfuscation',
        description: `Detected URL manipulation trick: ${domain}`
      });
    }
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
      score       += 18;
      confidence   = 90;
      threats.push({
        icon:        '🔢',
        category:    'IP Address Link',
        description: 'Link uses IP address rather than domain (highly suspicious)'
      });
    }
    if (domain.length > 40) {
      score       += 8;
      insights.push(`Unusually long domain: ${domain.substring(0,30)}...`);
    }
  });

  return { score: score, threats: threats, insights: insights, confidence: confidence };
}

function detectUrlObfuscation(url) {
  let score = 0;
  if (url.includes('@')) {
    score += 15;
  }
  if ((url.match(/%[0-9A-Fa-f]{2}/g) || []).length > 3) {
    score += 10;
  }
  if (url.split('.').length > 5) {
    score += 8;
  }
  if (/[0O][0O]|[1lI][1lI]|rn|vv/.test(url)) {
    score += 12;
  }
  return score;
}

// ============ 5. Brand Spoofing Detection ============

function brandSpoofingDetection(fromEmail, lowerText) {
  let score       = 0;
  const threats   = [];
  const insights  = [];
  let confidence  = 0;

  const senderDomain = getDomain(fromEmail).toLowerCase();

  BRAND_KEYWORDS.forEach(brand => {
    if (lowerText.includes(brand)) {
      if (!senderDomain.includes(brand) && !TRUSTED_DOMAINS.some(d => senderDomain.includes(d))) {
        score       += 20;
        confidence   = 90;
        threats.push({
          icon:        '🎭',
          category:    'Brand Impersonation',
          description: `Claiming from "${brand}" but sender domain is "${senderDomain}"`
        });
        const similarity = calculateStringSimilarity(brand, senderDomain);
        if (similarity > 0.6 && similarity < 0.95) {
          score       += 10;
          confidence   = 95;
          insights.push(`Domain "${senderDomain}" suspiciously similar to "${brand}" (${Math.round(similarity*100)}% match)`);
        }
      }
    }
  });

  return { score: score, threats: threats, insights: insights, confidence: confidence };
}

function calculateStringSimilarity(str1, str2) {
  const len1 = str1.length;
  const len2 = str2.length;
  const matrix = [];
  for (let i = 0; i <= len1; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= len2; j++) {
    matrix[0][j] = j;
  }
  for (let i = 1; i <= len1; i++) {
    for (let j = 1; j <= len2; j++) {
      if (str1[i-1] === str2[j-1]) {
        matrix[i][j] = matrix[i-1][j-1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i-1][j-1] + 1,
          matrix[i][j-1]   + 1,
          matrix[i-1][j]   + 1
        );
      }
    }
  }
  const distance = matrix[len1][len2];
  const maxLen   = Math.max(len1, len2);
  return 1 - (distance / maxLen);
}

// ============ HELPER FUNCTIONS ============

function getCurrentEmail() {
  try {
    const currentThread = GmailApp.getInboxThreads(0,1)[0];
    if (!currentThread) {
      return null;
    }
    const messages = currentThread.getMessages();
    const message  = messages[messages.length-1];
    return {
      subject: message.getSubject()   || 'No Subject',
      from:    message.getFrom()      || 'Unknown Sender',
      body:    message.getPlainBody() || '',
      date:    message.getDate()      || new Date()
    };
  } catch (error) {
    console.log('Error getting current email: ' + error);
    return null;
  }
}

function extractDomainsFromText(text) {
  const urlRegex = /https?:\/\/([\w\.-]+)/gi;
  const domains  = new Set();
  let match;
  while ((match = urlRegex.exec(text)) !== null) {
    domains.add(match[1].toLowerCase());
  }
  return Array.from(domains);
}

function getDomain(emailOrHost) {
  if (!emailOrHost) return '';
  const atIndex = emailOrHost.indexOf('@');
  const host    = (atIndex >= 0) ? emailOrHost.slice(atIndex + 1) : emailOrHost;
  const parts   = host.toLowerCase().split('.');
  if (parts.length < 2) return host;
  return parts.slice(-2).join('.');
}

function hasSuspiciousTld(hostname) {
  const parts = hostname.toLowerCase().split('.');
  const tld   = parts[parts.length-1];
  return SUSPICIOUS_TLDS.includes(tld);
}

function getRiskLevel(score) {
  if (score >= 70) {
    return { label: '🔴 Severe', color: '#d32f2f' };
  } else if (score >= 50) {
    return { label: '🟠 High', color: '#f57c00' };
  } else if (score >= 30) {
    return { label: '🟡 Medium', color: '#fbc02d' };
  } else if (score >= 15) {
    return { label: '🟢 Low', color: '#689f38' };
  } else {
    return { label: '✅ Safe', color: '#388e3c' };
  }
}

function generateRecommendations(score) {
  const recommendations = [];
  if (score >= 70) {
    recommendations.push('🚫 Do not click any links or download attachments');
    recommendations.push('🗑️ Delete this email immediately');
    recommendations.push('📢 Report to your email provider as phishing');
  } else if (score >= 50) {
    recommendations.push('⚠️ Avoid clicking links unless you can verify the sender');
    recommendations.push('✉️ Contact the supposed sender through official channels');
    recommendations.push('🔍 Inspect the sender’s email address carefully');
  } else if (score >= 30) {
    recommendations.push('🤔 Be cautious with this email');
    recommendations.push('🔗 Hover over links to verify destination before clicking');
  }
  return recommendations;
}

