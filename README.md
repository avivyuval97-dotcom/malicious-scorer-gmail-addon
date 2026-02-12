# Malicious Scorer 🛡️

**Malicious Scorer** is a cutting-edge Gmail security add-on designed for real-time detection of phishing, spoofing, and malware. By integrating global threat intelligence with Generative AI, it provides a comprehensive risk assessment for every incoming email.

---

## 🏗️ Architecture

The system follows a **Defense-in-Depth** multi-layered security model:

1.  **Identity Layer:** Inspects **SPF and DKIM** authentication results to verify sender legitimacy and prevent spoofing/BEC (Business Email Compromise) attacks.
2.  **Reputation Layer:** Executes asynchronous lookups against **VirusTotal** for all extracted URLs and file fingerprints (**SHA-256**) found within attachments.
3.  **Intelligence Layer (AI):** Utilizes **Gemini 2.5 Flash** to perform a semantic analysis of the email's intent, identifying social engineering patterns that traditional scanners often miss.
4.  **Enforcement Layer:** Aggregates all technical and AI signals into a weighted **Risk Score (0-100)**. High-risk senders are automatically moved to a persistent blacklist.



---

## 🔌 APIs Used

* **VirusTotal API (v3):** Global reputation engine for URLs and file hash lookups.
* **Google Gemini API (2.5 Flash):** Advanced Large Language Model for intent analysis and phishing detection.
* **Gmail Apps Script Service:** The core framework for accessing email metadata and building the native UI.
* **Properties Service:** A secure, persistent storage for managing the blacklist and API credentials.

---

## ✨ Implemented Features

* **Forensic File Analysis:** Computes SHA-256 hashes for all attachments to check against global malware databases without compromising privacy.
* **Semantic Threat Detection:** Gemini AI analyzes the subject and body to detect urgency, manipulation, and social engineering.
* **Automated & Manual Blacklisting:** Features a built-in **Blacklist Manager** allowing users to block or whitelist senders with a single click.
* **Dynamic Risk Scoring:** A transparent verdict system (Safe/Suspicious/Malicious) with detailed reasoning for every detection.
* **Analyst Debugging:** Includes a "Gemini Debug Log" feature for transparency into the AI's decision-making process.



---

## ⚠️ Limitations

* **API Quotas:** The free tier of VirusTotal is limited (typically 4 requests/min), which may impact performance for emails with a high number of links.
* **Archive Depth:** The scanner analyzes the hash of the archive file (ZIP/RAR) itself but does not currently decompress or inspect files hidden inside password-protected archives.
* **Persistent Storage Limit:** The blacklist is managed via `PropertiesService`, which has a 9KB size limit per property—ideal for personal use but not designed for massive enterprise lists.
* **OCR Integration:** The current AI analysis is text-optimized and does not perform OCR on images or scan visual-based phishing (e.g., screenshots of text).

---

### Developed by: yuval aviv

