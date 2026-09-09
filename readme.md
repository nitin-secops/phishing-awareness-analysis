# Phishing Awareness Analysis

A Python-based phishing detection tool that analyzes email headers and content using the same signal categories real SOC (Security Operations Center) analysts and email security gateways rely on: authentication protocol checks, content-based heuristics, and third-party threat intelligence.

Built as Project 3 for the Cyber Security Internship at **Decode Labs**.

> MITRE ATT&CK reference: Phishing maps to **T1566 (Phishing)** under the **Initial Access** tactic - it is typically an attacker's first step into a target environment.

## Project Structure

```
phishing-awareness-analysis/
├── main.py                 # CLI entry point (single email / batch analysis)
├── analyzer.py              # Content analysis: URLs, keywords, typosquatting
├── email_auth.py             # Header analysis: SPF/DKIM/DMARC, sender spoofing
├── threat_intel.py           # VirusTotal API integration (real + offline fallback)
├── config.py                  # Lightweight .env file loader (API key handling)
├── report_generator.py        # Combines all modules into a SOC-ticket-style report
├── .env.example                # Template for your API key (safe to commit)
├── .gitignore                   # Keeps your real .env (and __pycache__) out of Git
├── samples/                      # 10 realistic sample emails (6 phishing, 3 legit, 1 borderline)
├── README.md
└── tests/
    ├── test_analyzer.py           # 12 unit tests
    └── test_email_auth.py          # 11 unit tests
```

## How It Works: Three Layers of Evidence

Real phishing detection never relies on a single clue. This tool combines three independent evidence sources, each scored separately, into one final verdict:

### 1. Header Authentication (`email_auth.py`)
Parses raw email headers to check:
- **SPF (Sender Policy Framework)** - was the message sent from a server authorized by the domain owner?
- **DKIM (DomainKeys Identified Mail)** - does the message have a valid cryptographic signature?
- **DMARC (Domain-based Message Authentication)** - does the message pass the domain's own authentication policy?
- **Display name spoofing** - does the "From" name claim a known brand while the actual domain isn't one of that brand's official domains?
- **Reply-To mismatch** - does replying go somewhere different than the message claims to be from?

### 2. Content Analysis (`analyzer.py`)
Scans the message body for:
- **Typosquatted URLs** - lookalike domains detected via **Levenshtein (edit) distance** (e.g. `paypa1.com` is 1 edit away from `paypal.com`)
- **IP-based links** - URLs pointing to a raw IP address instead of a domain
- **URL shorteners** - links that hide their real destination
- **Urgency/fear language** - phrases designed to short-circuit careful thinking
- **Generic greetings** - "Dear Customer" instead of your actual name
- **Suspicious attachments** - dangerous or double file extensions (e.g. `invoice.pdf.exe`)

### 3. Threat Intelligence (`threat_intel.py`)
Looks up every URL found in the message against **VirusTotal**, which checks it against 70+ antivirus engines and security vendors. Supports:
- Live lookups (with your own free API key)
- Submitting new/unscanned URLs and polling for results
- **Graceful offline fallback** - if there's no API key or no internet, the tool keeps working using only the header and content signals, instead of crashing

All three layers feed into `report_generator.py`, which produces a final risk score, verdict (Likely Legitimate / Suspicious / Phishing), and a recommended action - the same structure a real SOC ticket follows.

## Setup

1. Install the one required dependency:
   ```bash
   pip install requests
   ```

2. (Optional, for live threat intelligence) Get a free API key at [virustotal.com](https://www.virustotal.com) → Sign up → Profile icon → API Key.

3. Copy `.env.example` to `.env` and paste your key:
   ```
   VT_API_KEY=your_real_key_here
   ```
   Without this step, the tool still works fully - it just skips live VirusTotal lookups and reports "offline" for URL reputation.

## Usage

```bash
python3 main.py
```

**Option 1 - Analyze a single email**: paste raw email text (headers + body) or point to a file.

**Option 2 - Batch analyze**: runs all 10 sample emails in `samples/` and prints a summary table, similar to a SOC analyst triaging a queue.

### Example Output

```
============================================================
PHISHING ANALYSIS REPORT - Case #001
============================================================
Final Verdict : Phishing
Total Risk Score : 22

--- Header / Authentication Findings ---
  [!] SPF check FAILED - sending server is not authorized for this domain
  [!] DKIM check is 'none' - message signature missing or invalid
  [!] DMARC check FAILED - this message fails the domain's own authentication policy
  [!] Display name claims to be 'paypal' but actual domain is 'paypa1-alerts.com'
  [!] Reply-To domain does not match From domain

--- Content Findings ---
  [!] Link 'http://paypa1.com/verify-account' closely resembles legitimate domain 'paypal.com' (edit distance 1) - likely typosquatting
  [!] Uses urgency/fear language: account will be suspended, verify your account, unusual activity
  [!] Uses a generic greeting ('dear customer') instead of your actual name

--- URL Threat Intelligence (VirusTotal) ---
  URL: http://paypa1.com/verify-account
    Mode: offline | Verdict: Unknown (offline)
    Note: No VirusTotal API key configured - skipped live lookup.

--- Recommended Action ---
  Block sender domain, quarantine similar messages, and notify affected users. Escalate to Tier 2 if user reports credential entry or financial loss.
============================================================
```

## Running the Tests

```bash
cd tests
python3 test_analyzer.py
python3 test_email_auth.py
```

23 tests total, all passing.

## Bugs Found and Fixed During Development

Testing against realistic samples surfaced two real detection flaws:

1. **False negative from substring matching**: a lookalike domain like `netflix-billing-support.com` was initially cleared as "not spoofed" because it happened to contain the word "netflix". Fixed by checking for an exact match (or proper subdomain) against a list of the brand's real official domains, instead of simple substring containment.

2. **False positive introduced by that fix**: the stricter check then incorrectly flagged `amazon.in` (a legitimate regional Amazon domain) as spoofed. Fixed by mapping each brand to a list of its known official domains rather than just one.

Both fixes have dedicated regression tests (`test_display_name_spoofing_not_flagged_for_lookalike_substring` and `test_display_name_spoofing_not_flagged_for_real_domain`) so the bugs can't silently reappear.

## Skills Demonstrated

- Threat analysis and security thinking (identifying real phishing indicators, not just keyword matching)
- MITRE ATT&CK framework awareness (T1566 - Phishing)
- Email authentication protocols: SPF, DKIM, DMARC
- String algorithms: Levenshtein distance for typosquatting detection
- REST API integration with an external threat intelligence platform (VirusTotal), including asynchronous submit-and-poll workflows
- Secure credential management (`.env` files, `.gitignore`, never hardcoding secrets)
- Fault-tolerant design (graceful degradation when an external API is unavailable)
- Weighted risk scoring and SOC-style incident reporting
- Debugging and regression testing (found and fixed two real detection bugs during development)

## Author

Nitin Yadav — Cyber Security Intern at Decode Labs
