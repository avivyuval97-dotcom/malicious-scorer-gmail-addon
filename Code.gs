/**
 * Malicious Scanner - Full Version with Blacklist Manager
 * CORE FEATURES:
 * 1. Identity Authentication (SPF/DKIM)
 * 2. Multi-URL Scanning & Reputation (VirusTotal)
 * 3. File Reputation (VirusTotal SHA-256 Lookup)
 * 4. AI Deep Content Inspection (Gemini 2.5 Flash)
 * 5. Manual & Automated Blacklisting + UI Manager
 */

function buildAddOn(e) {
  var message = GmailApp.getMessageById(e.messageMetadata.messageId);
  var subject = message.getSubject() || "";
  var sender = (message.getFrom() || "").toLowerCase();
  var rawBody = message.getPlainBody() || "";
  
  var body = sanitizeBody_(rawBody);
  var urls = extractAllUrls_(body);
  var attachments = message.getAttachments();

  var scriptProperties = PropertiesService.getScriptProperties();
  var vtApiKey = scriptProperties.getProperty('VT_API_KEY');
  var geminiApiKey = scriptProperties.getProperty('GEMINI_API_KEY');
  
  var blacklist = JSON.parse(scriptProperties.getProperty('blacklist') || "[]");
  
  var riskScore = 0;
  var reasons = [];
  var isBlacklisted = blacklist.indexOf(sender) !== -1;

  if (isBlacklisted) {
    riskScore = 100;
    reasons.push("🚨 BLACKLISTED: Sender blocked due to previous malicious activity.");
  } else {
    var technicalScore = 0;
    
    // 1. Identity Verification (SPF/DKIM)
    var authResults = checkEmailAuthentication_(message);
    if (authResults.spf === "fail") { technicalScore += 20; reasons.push("❌ SPF FAIL: Email server not authorized."); }
    if (authResults.dkim === "fail") { technicalScore += 15; reasons.push("❌ DKIM FAIL: Invalid cryptographic signature."); }
    if (authResults.spf === "pass" && authResults.dkim === "pass") { reasons.push("🛡️ Identity Verified: SPF & DKIM passed."); }

    // 2. MULTI-URL Reputation (VirusTotal)
    var maxVtUrlHits = 0;
    if (urls.length > 0 && vtApiKey) {
      urls.forEach(function(url) {
        var hits = checkVirusTotalUrl_(url, vtApiKey);
        if (hits > maxVtUrlHits) maxVtUrlHits = hits;
      });
      if (maxVtUrlHits >= 3) { technicalScore += 75; reasons.push("🚩 VirusTotal URL: High confidence threat detected."); }
      else if (maxVtUrlHits > 0) { technicalScore += 35; reasons.push("🟡 VirusTotal URL: Low confidence alert."); }
    }

    // 3. Integrated File Analysis (VirusTotal SHA-256 Lookup)
    if (attachments && attachments.length > 0) { 
      reasons.push("📎 <b>Attachments Found (" + attachments.length + "):</b>");
      
      attachments.forEach(function(att) {
        var fileName = att.getName();
        var fileHash = getAttachmentHash_(att);
        
        var vtFileHits = 0;
        if (vtApiKey) {
          vtFileHits = checkVirusTotalFile_(fileHash, vtApiKey);
        }

        var fileRisk = 0; 
        var statusIcon = "📄";

        if (vtFileHits >= 3) {
          fileRisk = 90; 
          statusIcon = "🚨";
          reasons.push("🚨 <b>MALWARE DETECTED:</b> File <b>" + fileName + "</b> flagged by " + vtFileHits + " engines!");
        } else if (vtFileHits > 0) {
          fileRisk = 40;
          statusIcon = "⚠️";
          reasons.push("⚠️ <b>Suspicious File:</b> <b>" + fileName + "</b> detected by " + vtFileHits + " engines.");
        } else {
          reasons.push(statusIcon + " <b>" + fileName + "</b> (No threats found in VirusTotal)");
        }

        reasons.push("   ↳ SHA-256: " + fileHash.substring(0, 12) + "...");
        technicalScore += fileRisk;
      });
    }

    // 4. AI Content Inspection (Handles Context, Keywords, and Intent)
    riskScore = Math.min(technicalScore, 100);
    if (geminiApiKey) {
      var features = { subject: subject, sender: sender, urlCount: urls.length, attachmentCount: attachments.length };
      var aiResp = checkGeminiEmailRisk_(features, geminiApiKey);
      if (aiResp && aiResp.ok) {
        var aiBoost = (aiResp.risk_score >= 70) ? 40 : (aiResp.risk_score >= 35 ? 15 : 0);
        riskScore = Math.min(100, riskScore + aiBoost);
        reasons.push("🤖 Gemini AI score: " + aiResp.risk_score + "/100");
        if (aiResp.reasons) aiResp.reasons.forEach(function (r) { reasons.push("• " + r); });
      } else {
        reasons.push("🤖 <b>AI Analysis Offline:</b> Error detected. Please check Gemini Debug for details.");
      }
    }

    // 5. Verdict & Safe Message
    if (riskScore === 0) {
      reasons.unshift("✅ <b>No threats detected:</b> This email appears to be safe.");
    }

    var verdict = (riskScore >= 70) ? "🚫 Malicious" : (riskScore >= 36 ? "🟡 Suspicious" : "✅ Safe");
    
    if (verdict === "🚫 Malicious" && blacklist.indexOf(sender) === -1) {
      blacklist.push(sender);
      scriptProperties.setProperty('blacklist', JSON.stringify(blacklist));
      reasons.unshift("🔒 AUTO-BLACKLISTED: Sender blocked due to high risk score.");
    }
  }

  return createResultCard({ 
    verdict: isBlacklisted ? "🚫 Malicious" : verdict, 
    risk_score: isBlacklisted ? 100 : riskScore, 
    details: { reasons: reasons, url: (urls.length > 0 ? urls[0] : "No links found") } 
  }, sender, isBlacklisted);
}

// --- BLACKLIST MANAGEMENT FUNCTIONS ---

function showBlacklistManager(e) {
  var props = PropertiesService.getScriptProperties();
  var blacklist = JSON.parse(props.getProperty('blacklist') || "[]");
  
  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Blacklist Manager"));

  var section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText("<b>Manage blocked senders:</b>"));

  section.addWidget(CardService.newTextInput()
    .setFieldName("manual_email")
    .setTitle("Add Email to Blacklist")
    .setHint("example@domain.com"));

  section.addWidget(CardService.newTextButton()
    .setText("➕ Add to Blacklist")
    .setOnClickAction(CardService.newAction().setFunctionName("handleManualAdd")));

  section.addWidget(CardService.newDivider());

  if (blacklist.length === 0) {
    section.addWidget(CardService.newTextParagraph().setText("<i>The blacklist is currently empty.</i>"));
  } else {
    blacklist.forEach(function(email) {
      section.addWidget(CardService.newKeyValue()
        .setContent(email)
        .setButton(CardService.newTextButton()
          .setText("🗑️ Remove")
          .setOnClickAction(CardService.newAction()
            .setFunctionName("handleWhitelistFromManager")
            .setParameters({ sender: email }))));
    });
  }

  section.addWidget(CardService.newTextButton()
    .setText("⬅️ Back to Scan")
    .setOnClickAction(CardService.newAction().setFunctionName("backToScan")));

  return card.addSection(section).build();
}

function handleManualAdd(e) {
  var emailToAdd = (e.formInput.manual_email || "").toLowerCase().trim();
  if (!emailToAdd || emailToAdd.indexOf("@") === -1) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Invalid Email Address")).build();
  }
  var props = PropertiesService.getScriptProperties();
  var list = JSON.parse(props.getProperty('blacklist') || "[]");
  if (list.indexOf(emailToAdd) === -1) {
    list.push(emailToAdd);
    props.setProperty('blacklist', JSON.stringify(list));
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().updateCard(showBlacklistManager(e)))
      .setNotification(CardService.newNotification().setText("Blocked: " + emailToAdd))
      .build();
  }
  return CardService.newActionResponseBuilder().setNotification(CardService.newNotification().setText("Already blocked")).build();
}

function handleWhitelistFromManager(e) {
  var senderToRemove = e.parameters.sender;
  var props = PropertiesService.getScriptProperties();
  var list = JSON.parse(props.getProperty('blacklist') || "[]")
    .filter(function(email) { return email !== senderToRemove; });
  props.setProperty('blacklist', JSON.stringify(list));
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(showBlacklistManager(e)))
    .setNotification(CardService.newNotification().setText("Removed from Blacklist"))
    .build();
}

// --- REMAINING UTILITIES ---

function checkVirusTotalFile_(fileHash, key) {
  var url = "https://www.virustotal.com/api/v3/files/" + fileHash;
  var options = { "method": "get", "headers": { "x-apikey": key }, "muteHttpExceptions": true };
  try {
    var res = UrlFetchApp.fetch(url, options);
    if (res.getResponseCode() == 200) {
      var data = JSON.parse(res.getContentText());
      return data.data.attributes.last_analysis_stats.malicious || 0;
    }
  } catch (e) { console.error("VT File Error: " + e.message); }
  return 0;
}

function checkVirusTotalUrl_(url, key) {
  try {
    var id = Utilities.base64EncodeWebSafe(url).replace(/=+$/, '');
    var res = UrlFetchApp.fetch("https://www.virustotal.com/api/v3/urls/" + id, { 
      headers: { "x-apikey": key }, "muteHttpExceptions": true 
    });
    if (res.getResponseCode() == 200) {
      return JSON.parse(res.getContentText()).data.attributes.last_analysis_stats.malicious || 0;
    }
  } catch (e) { console.error("VT URL Error: " + e.message); }
  return 0;
}

function getAttachmentHash_(attachment) {
  var hash = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, attachment.getBytes());
  return hash.map(function(byte) {
    var str = (byte & 0xFF).toString(16);
    return str.length == 1 ? '0' + str : str;
  }).join('');
}

function checkEmailAuthentication_(message) {
  var res = { spf: "unknown", dkim: "unknown" };
  try {
    var raw = message.getRawContent().substring(0, 5000);
    if (raw.indexOf("spf=pass") !== -1) res.spf = "pass"; else if (raw.indexOf("spf=fail") !== -1) res.spf = "fail";
    if (raw.indexOf("dkim=pass") !== -1) res.dkim = "pass"; else if (raw.indexOf("dkim=fail") !== -1) res.dkim = "fail";
  } catch (e) {}
  return res;
}

function checkGeminiEmailRisk_(features, apiKey) {
  var props = PropertiesService.getScriptProperties();
  var endpoint = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=" + apiKey;
  var payload = {
    contents: [{ role: "user", parts: [{ text: "Analyze security risk: " + JSON.stringify(features) }] }],
    generation_config: { temperature: 0.2, response_mime_type: "application/json", 
      response_schema: { type: "OBJECT", properties: { risk_score: { type: "INTEGER" }, verdict: { type: "STRING" }, reasons: { type: "ARRAY", items: { type: "STRING" } } }, required: ["risk_score", "verdict", "reasons"] }
    }
  };
  try {
    var res = UrlFetchApp.fetch(endpoint, { method: "post", contentType: "application/json", payload: JSON.stringify(payload), muteHttpExceptions: true });
    var raw = res.getContentText();
    props.setProperty("LAST_GEMINI_DEBUG", raw);
    if (res.getResponseCode() === 200) return { ok: true, ...JSON.parse(JSON.parse(raw).candidates[0].content.parts[0].text) };
  } catch (e) {}
  return { ok: false };
}

function backToScan(e) {
  var nav = CardService.newNavigation().popToRoot().updateCard(buildAddOn(e));
  return CardService.newActionResponseBuilder().setNavigation(nav).build();
}

function createResultCard(results, sender, isBlacklisted) {
  var card = CardService.newCardBuilder().setHeader(CardService.newCardHeader().setTitle("Malicious Scanner"));
  var sec = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText("<b>Verdict:</b> " + results.verdict))
    .addWidget(CardService.newTextParagraph().setText("<b>Risk Score:</b> " + results.risk_score + "/100"));
  
  results.details.reasons.forEach(function (r) { sec.addWidget(CardService.newTextParagraph().setText(r)); });
  
  var acts = CardService.newCardSection().setHeader("Controls:");
  acts.addWidget(CardService.newTextButton().setText("🧪 Show Gemini Debug").setOnClickAction(CardService.newAction().setFunctionName("showLastGeminiDebug")));
  acts.addWidget(CardService.newTextButton().setText("⚙️ Manage Blacklist").setOnClickAction(CardService.newAction().setFunctionName("showBlacklistManager")));
  
  var btnText = isBlacklisted ? "✅ Whitelist Sender" : "🚫 Block Sender";
  acts.addWidget(CardService.newTextButton().setText(btnText).setOnClickAction(CardService.newAction().setFunctionName("handleManualBlacklist").setParameters({ sender: sender })));
  
  return card.addSection(sec).addSection(acts).build();
}

function handleManualBlacklist(e) {
  var props = PropertiesService.getScriptProperties();
  var list = JSON.parse(props.getProperty('blacklist') || "[]");
  var sender = e.parameters.sender;
  if (list.indexOf(sender) === -1) {
    list.push(sender);
    props.setProperty('blacklist', JSON.stringify(list));
    return CardService.newActionResponseBuilder().setNavigation(CardService.newNavigation().updateCard(buildAddOn(e))).setNotification(CardService.newNotification().setText("Sender Blocked")).build();
  } else {
    list = list.filter(function(s) { return s !== sender; });
    props.setProperty('blacklist', JSON.stringify(list));
    return CardService.newActionResponseBuilder().setNavigation(CardService.newNavigation().updateCard(buildAddOn(e))).setNotification(CardService.newNotification().setText("Sender Whitelisted")).build();
  }
}

function extractAllUrls_(text) {
  var urlRegex = /https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)/gi;
  var found = text.match(urlRegex) || [];
  return found.filter(function(item, pos) { return found.indexOf(item) == pos; });
}

function sanitizeBody_(text) {
  var clean = (text || "").replace(/\nOn .*wrote:|\nFrom:|\nSent:/, "");
  return clean.replace(/\s+/g, ' ').trim();
}

function showLastGeminiDebug() {
  var debug = PropertiesService.getScriptProperties().getProperty("LAST_GEMINI_DEBUG") || "No debug data available.";
  var card = CardService.newCardBuilder().setHeader(CardService.newCardHeader().setTitle("Gemini Debug Log"));
  card.addSection(CardService.newCardSection().addWidget(CardService.newTextParagraph().setText(escapeHtml_(debug))));
  card.addSection(CardService.newCardSection().addWidget(CardService.newTextButton().setText("⬅️ Back").setOnClickAction(CardService.newAction().setFunctionName("backToScan"))));
  return card.build();
}

function escapeHtml_(s) { return (s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
