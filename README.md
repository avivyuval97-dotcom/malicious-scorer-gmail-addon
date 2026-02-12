# Malicious Scorer 🛡️

**Malicious Scorer** is a high-performance Gmail security add-on designed to identify and neutralize cyber threats in real-time. It leverages a combination of deterministic technical checks, global threat intelligence via VirusTotal, and generative AI (Gemini) to provide a comprehensive security verdict for every incoming email.

---

## 🏗️ Architecture

The application follows a **Defense-in-Depth** multi-layered security model:

1.  **Identity Layer:** Inspects **SPF and DKIM** headers to verify sender authenticity and prevent email spoofing.
2.  **Reputation Layer:** Executes asynchronous lookups against **VirusTotal** for unique URLs and file fingerprints (**SHA-256**) found within the email.
3.  **Semantic Layer:** Utilizes **Gemini 2.5 Flash** to analyze the email context, subject lines, and metadata for social engineering and phishing patterns.
4.  **Enforcement Layer:** Aggregates signals into a unified **Risk Score (0-100)** and triggers automated blacklisting for high-risk senders using persistent local storage.



---

## 🔌 APIs Used

* **VirusTotal API (v3):** Used for dual-purpose reputation analysis of both URLs and file fingerprints.
* **Google Gemini API (2.5 Flash):** Provides qualitative reasoning to detect intent-based threats (Phishing/Scams).
* **Gmail Apps Script Service:** Facilitates deep message parsing, attachment extraction, and header verification.
* **Properties Service:** Functions as a secure, persistent Key-Value store for local blacklist management.

---

## ✨ Implemented Features

* **Forensic SHA-256 Hashing:** Automatically generates digital fingerprints for all attachments to ensure data integrity.
* **Multi-Engine File Reputation:** Cross-references file hashes with VirusTotal’s database to identify known malware via 70+ security vendors.
* **URL Threat Detection:** Scans all extracted links against global blacklists in real-time.
* **AI Context Analysis:** Deep inspection of email features to identify sophisticated social engineering.
* **Full Blacklist Lifecycle Management:** A dedicated UI to manually or automatically block/whitelist senders.
* **Safe Verdict UI:** Displays a clear "No threats detected" confirmation when the risk score is zero.
* **Analyst Toolkit:** Includes a "Gemini Debug Log" for transparency and direct links to **ANY.RUN** for interactive sandboxing.



---

## ⚠️ Limitations

* **API Rate Limits:** The free tier of VirusTotal is limited (typically 4 requests/min), which may impact performance for emails with numerous links.
* **Archive Inspection:** The scanner computes the hash of the archive file (ZIP/RAR) itself but does not decompress or inspect files hidden inside nested archives.
* **Storage Cap:** The blacklist is stored via `PropertiesService`, which has a 9KB limit—suitable for personal use but not for enterprise-scale lists.
* **OCR & Media:** The AI engine is text-optimized; it does not currently perform OCR on images or scan password-protected files.

---

### Developed by: [Your Name]
*Project: Malicious Scorer Security Suite for Gmail*
