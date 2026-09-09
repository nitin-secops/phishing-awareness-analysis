"""
analyzer.py
-----------
Core detection engine for phishing analysis.

This module looks at the BODY and CONTENT of a message (not headers -
that's email_auth.py's job) and extracts "signals": individual pieces
of evidence that something might be malicious. Each signal is scored
and combined into an overall risk score.

This mirrors how a real SOC L1 analyst thinks: never trust one clue,
look at several independent signals together.
"""

import re
from urllib.parse import urlparse

# Well-known brands that attackers commonly impersonate.
# Used to detect "typosquatting" - lookalike domains such as
# paypa1.com instead of paypal.com.
COMMONLY_SPOOFED_BRANDS = [
    "paypal.com", "amazon.com", "microsoft.com", "apple.com",
    "google.com", "netflix.com", "facebook.com", "bankofamerica.com",
    "chase.com", "wellsfargo.com", "linkedin.com", "instagram.com",
]

# Known URL-shortening services. Shorteners hide the real destination
# of a link, which is exactly why phishers like them.
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly",
]

# Phrases that create urgency or fear - classic social engineering.
# Real phishing research consistently finds these patterns because
# a panicked reader is less likely to think critically.
URGENCY_PHRASES = [
    "act now", "act immediately", "urgent action required",
    "account will be suspended", "account has been suspended",
    "verify your account", "confirm your identity",
    "unusual activity", "your account will be locked",
    "limited time", "expires today", "final notice",
    "click here immediately", "immediate attention",
    "failure to comply", "your payment failed",
    "unauthorized login attempt", "security alert",
]

# Generic greetings are common in mass-sent phishing emails, since
# the attacker doesn't actually know your name.
GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear valued customer",
    "dear account holder", "dear member", "hello user",
]

# File extensions that are suspicious, especially when disguised
# with a double extension like "invoice.pdf.exe".
DANGEROUS_EXTENSIONS = [".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".jar"]


def extract_urls(text: str) -> list:
    """Find all URLs in a block of text using a simple regex."""
    url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
    return re.findall(url_pattern, text)


def levenshtein_distance(a: str, b: str) -> int:
    """
    Calculate the Levenshtein (edit) distance between two strings -
    the minimum number of single-character edits (insertions,
    deletions, substitutions) needed to turn one string into the other.

    This is the standard algorithm used to detect typosquatting:
    'paypa1.com' is edit-distance 1 away from 'paypal.com'.
    """
    if len(a) < len(b):
        return levenshtein_distance(b, a)
    if len(b) == 0:
        return len(a)

    previous_row = range(len(b) + 1)
    for i, char_a in enumerate(a):
        current_row = [i + 1]
        for j, char_b in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (char_a != char_b)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def get_domain(url: str) -> str:
    """Extract just the domain (netloc) from a URL, lowercased."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    return parsed.netloc.lower()


def analyze_urls(urls: list) -> dict:
    """
    Analyze a list of URLs for common phishing indicators:
    - typosquatting (lookalike domains)
    - IP-address-based links (no domain name at all)
    - known URL shorteners (hides real destination)
    """
    findings = {
        "typosquatted_domains": [],
        "ip_based_urls": [],
        "shortened_urls": [],
    }

    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

    for url in urls:
        domain = get_domain(url)
        domain_without_port = domain.split(":")[0]

        # Check for IP-based URLs (e.g. http://192.168.1.1/login)
        if ip_pattern.match(domain_without_port):
            findings["ip_based_urls"].append(url)
            continue

        # Check for known shorteners
        if any(domain_without_port == shortener for shortener in URL_SHORTENERS):
            findings["shortened_urls"].append(url)
            continue

        # Check for typosquatting against known brands.
        # A small edit distance (1 or 2) to a real brand domain,
        # while NOT being an exact match, is a strong red flag.
        for brand in COMMONLY_SPOOFED_BRANDS:
            distance = levenshtein_distance(domain_without_port, brand)
            if 0 < distance <= 2:
                findings["typosquatted_domains"].append((url, brand, distance))
                break

    return findings


def find_urgency_language(text: str) -> list:
    """Return which urgency/fear phrases appear in the text."""
    text_lower = text.lower()
    return [phrase for phrase in URGENCY_PHRASES if phrase in text_lower]


def find_generic_greeting(text: str) -> list:
    """Return which generic greetings appear in the text."""
    text_lower = text.lower()
    return [greeting for greeting in GENERIC_GREETINGS if greeting in text_lower]


def find_suspicious_attachments(text: str) -> list:
    """
    Look for filenames mentioned in the text that end in a dangerous
    extension, especially double extensions like 'invoice.pdf.exe'
    (designed to look like a harmless PDF at a glance).

    We match single "word.word.ext" style tokens rather than whole
    phrases, so a sentence mentioning a filename doesn't get captured
    in its entirety.
    """
    filename_pattern = r'\b[\w-]+(?:\.[\w-]+)+\b'
    candidates = re.findall(filename_pattern, text)

    suspicious = []
    for candidate in candidates:
        for ext in DANGEROUS_EXTENSIONS:
            if candidate.lower().endswith(ext):
                suspicious.append(candidate)
                break

    return suspicious


def calculate_risk_score(signals: dict) -> dict:
    """
    Combine all detected signals into a weighted score and a final
    verdict. Weights reflect how strong an individual signal is on
    its own (e.g. a typosquatted domain is a much stronger indicator
    than a single urgency phrase).
    """
    score = 0
    reasons = []

    if signals["typosquatted_domains"]:
        score += 4
        for url, brand, distance in signals["typosquatted_domains"]:
            reasons.append(
                f"Link '{url}' closely resembles legitimate domain "
                f"'{brand}' (edit distance {distance}) - likely typosquatting"
            )

    if signals["ip_based_urls"]:
        score += 3
        reasons.append(
            f"Found {len(signals['ip_based_urls'])} link(s) using a raw IP "
            f"address instead of a domain name - legitimate organizations "
            f"almost never do this"
        )

    if signals["shortened_urls"]:
        score += 2
        reasons.append(
            f"Found {len(signals['shortened_urls'])} shortened URL(s) - "
            f"these hide the real destination"
        )

    if signals["urgency_phrases"]:
        score += min(len(signals["urgency_phrases"]), 3)
        reasons.append(
            f"Uses urgency/fear language: {', '.join(signals['urgency_phrases'][:3])}"
        )

    if signals["generic_greetings"]:
        score += 1
        reasons.append(
            f"Uses a generic greeting ('{signals['generic_greetings'][0]}') "
            f"instead of your actual name"
        )

    if signals["suspicious_attachments"]:
        score += 4
        reasons.append(
            f"Mentions suspicious attachment(s): {', '.join(signals['suspicious_attachments'])}"
        )

    if score >= 6:
        verdict = "Phishing"
    elif score >= 3:
        verdict = "Suspicious"
    else:
        verdict = "Likely Legitimate"

    return {"score": score, "verdict": verdict, "reasons": reasons}


def analyze_message(text: str) -> dict:
    """
    Run the full content-analysis pipeline on a message body and
    return all findings plus a final risk verdict.
    """
    urls = extract_urls(text)
    url_findings = analyze_urls(urls)

    signals = {
        "urls_found": urls,
        "typosquatted_domains": url_findings["typosquatted_domains"],
        "ip_based_urls": url_findings["ip_based_urls"],
        "shortened_urls": url_findings["shortened_urls"],
        "urgency_phrases": find_urgency_language(text),
        "generic_greetings": find_generic_greeting(text),
        "suspicious_attachments": find_suspicious_attachments(text),
    }

    risk = calculate_risk_score(signals)

    return {**signals, **risk}
