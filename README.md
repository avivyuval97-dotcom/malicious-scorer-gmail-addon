# Malicious Scorer 🛡️

![Google Apps Script](https://img.shields.io/badge/Google%20Apps%20Script-4285F4?style=for-the-badge&logo=google-apps-script&logoColor=white)
![JavaScript](https://img.shields.io/badge/javascript-%23323330.svg?style=for-the-badge&logo=javascript&logoColor=%23F7DF1E)
![Gemini AI](https://img.shields.io/badge/Gemini%20AI-8E75C2?style=for-the-badge&logo=googlegemini&logoColor=white)

**Malicious Scorer** is a high-performance Gmail security add-on designed to identify and neutralize cyber threats in real-time. This project is built and hosted entirely on the **Google Apps Script (GAS)** cloud platform, integrating directly with the Gmail interface to provide a seamless, serverless security layer.

---

## 🏗️ Architecture & Environment

The application is developed using the **V8 Runtime** of Google Apps Script. It executes on Google's infrastructure (Server-side) and interacts with the Gmail UI through the **Card Service**.

The security model follows a **Defense-in-Depth** approach:

1.  **Identity Layer:** Inspects **SPF and DKIM** headers via the native `GmailApp` service to verify sender authenticity and mitigate spoofing risks.
2.  **Reputation Layer:** Performs asynchronous lookups against **VirusTotal** for all extracted URLs and file fingerprints (**SHA-256**) using the `UrlFetchApp` service.
3.  **Intelligence Layer (AI):** Leverages **Gemini 2.5 Flash** (via external API request) to conduct semantic analysis of the email's intent, specifically targeting social engineering and manipulation patterns.
4.  **Enforcement Layer:** Aggregates all security signals into a unified **Risk Score (0-100)** and manages a persistent blacklist using the platform's built-in `PropertiesService`.

---

## 🔒 Security & Privacy Considerations

A core principle of this project is **Data Minimization** and user privacy:
* **Hash-Only Scanning:** When inspecting attachments, the system computes a local **SHA-256 hash** and only sends the fingerprint to VirusTotal. The actual file content is never uploaded to external servers.
* **Privacy-First AI:** Only non-sensitive metadata (subject, sender, and counts) is sent for AI analysis to identify patterns without exposing the full private body of the email unless necessary.

---

## 🛠️ Error Handling & Resilience

The system is built to be **Resilient** in production environments:
* **Graceful Degradation:** If an external API (like VirusTotal or Gemini) is unreachable, the system continues to function based on the remaining layers and provides a "Partial Scan" notification to avoid a false sense of security.
* **Input Sanitization:** All email bodies are sanitized before processing to prevent script injection and to ensure the AI receives clean, relevant data.

---

## 📂 Project Structure

* **`Code.gs` (Core Logic):** Handles orchestration, scanning engines (Hashing, Regex), API integrations, and UI rendering.
* **`appsscript.json` (Manifest):** Defines OAuth Scopes and contextual triggers.

---

## 🚀 Future Roadmap (TODO)

1.  **Dynamic Sandbox Analysis:** Integration with **ANY.RUN** or **Cuckoo Sandbox** for behavioral detection of suspicious files.
2.  **Secure Secret Management:** Transitioning API key storage to **GCP Secret Manager** for IAM-based access control and encryption.
3.  **Advanced Caching Layer:** Implementation of `CacheService` to reduce API latency and costs.
4.  **URL Unshortening:** Resolving shortened URLs (e.g., bit.ly) before analysis.
5.  **Image-Based Phishing (OCR):** Integrating **Google Vision API** to detect malicious text within images.

---

## ⚠️ Limitations

* **API Quotas:** Free tier VirusTotal limits (4 requests/min).
* **Encrypted Archives:** Cannot inspect files inside password-protected ZIP/RAR files.
* **Storage Constraints:** `PropertiesService` has a 9KB size limit per key.

---

### Developed by: [Your Name]
*Industrial Engineering & Management Student | AI-Driven Security Systems Developer*
