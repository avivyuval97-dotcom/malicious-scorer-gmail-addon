# Malicious Scorer 🛡️

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
* **Privacy-First AI:** Only relevant metadata (subject, sender, and counts) is processed for AI analysis to identify patterns without exposing the full private body of the email unless necessary for intent detection.

---

## 🛠️ Error Handling & Resilience

The system is built to be **Resilient** in production environments:
* **Graceful Degradation:** If an external API (like VirusTotal or Gemini) is unreachable, the system continues to function based on the remaining layers and provides a "Partial Scan" notification to avoid a false sense of security.
* **Input Sanitization:** All email bodies are sanitized before processing to prevent script injection and to ensure the AI receives clean, relevant data.

---

## 📂 Project Structure

* **`Code.gs` (Core Logic):** Handles orchestration, scanning engines (Hashing, Regex), API integrations, and UI rendering.
* **`appsscript.json` (Manifest):** Defines OAuth Scopes (permissions) and contextual triggers that activate the add-on when a message is opened.

---

## 🚀 Future Roadmap (TODO)

To transform this MVP into a production-grade enterprise security tool, the following upgrades are planned:

1.  **Dynamic Sandbox Analysis:** Integration with **ANY.RUN** or **Cuckoo Sandbox** for behavioral detection of suspicious files in isolated environments.

2.  **Secure Secret Management:** Transitioning API key storage from `PropertiesService` to **GCP Secret Manager**. This enables IAM-based access control, secret rotation, and encrypted storage.

3.  **Advanced Caching Layer:** Implementation of a caching mechanism (using `CacheService` or Redis) to store previous scan results, reducing API latency and costs.
4.  **URL Unshortening:** Developing a pre-scan layer to resolve shortened URLs (e.g., bit.ly) to their final destination before analysis.
5.  **Image-Based Phishing (OCR):** Integrating **Google Vision API** to detect malicious text within images and screenshots.

---

## ⚠️ Limitations

* **API Quotas:** The free tier of VirusTotal is limited (typically 4 requests/min), which may impact performance for emails with numerous links.
* **Encrypted Archives:** The scanner analyzes the hash of the archive file itself but cannot currently inspect files hidden inside password-protected ZIP/RAR files.
* **Storage Constraints:** `PropertiesService` has a 9KB size limit per key—sufficient for personal use but not intended for massive enterprise-scale lists.

---

### Developed by: yuval aviv
