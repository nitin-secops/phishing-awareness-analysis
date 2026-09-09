"""
email_auth.py
-------------
Parses raw email HEADERS (not body) to check authentication results
and sender spoofing - the same signals real email security gateways
(Google, Microsoft, Proofpoint, etc.) rely on.

Three protocols matter here:

  SPF (Sender Policy Framework)
      Checks whether the sending mail server's IP is authorized to
      send mail for that domain. A "fail" means the message came
      from a server the real domain owner never approved.

  DKIM (DomainKeys Identified Mail)
      A cryptographic signature attached to the email. If the
      signature doesn't verify, the message (or its headers) may
      have been altered in transit, or it was never signed by the
      real domain at all.

  DMARC (Domain-based Message Authentication, Reporting & Conformance)
      A policy layer on top of SPF/DKIM that tells receiving servers
      what to do if both checks fail (reject, quarantine, or do
      nothing). A DMARC "fail" is a strong signal of spoofing.
"""

import re

# Maps a brand name (as it might appear in a display name) to a list
# of its real, official domains. Large companies often operate several
# regional domains (e.g. amazon.in, amazon.co.uk), so a single-domain
# check would incorrectly flag their legitimate regional mail as
# spoofed. This is also used to catch lookalike domains that merely
# *contain* the brand name (e.g. "netflix-billing-support.com")
# without actually being one of the real domains.
COMMONLY_IMPERSONATED_BRANDS = {
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com"],
    "netflix": ["netflix.com"],
    "bank of america": ["bankofamerica.com"],
    "chase": ["chase.com"],
    "wells fargo": ["wellsfargo.com"],
    "linkedin": ["linkedin.com"],
    "irs": ["irs.gov"],
    "instagram": ["instagram.com"],
    "facebook": ["facebook.com"],
}


def parse_headers(raw_email: str) -> dict:
    """
    Parse simple "Key: Value" style headers from raw email text.
    Stops at the first blank line, which conventionally separates
    headers from the message body.

    This is a simplified parser for teaching purposes - real mail
    parsers (like Python's own `email` module) handle far more edge
    cases (folded headers spanning multiple lines, encodings, etc).
    """
    headers = {}
    lines = raw_email.splitlines()

    current_key = None
    for line in lines:
        if line.strip() == "":
            break  # blank line = end of headers, start of body

        # Folded header continuation (starts with whitespace)
        if line.startswith((" ", "\t")) and current_key:
            headers[current_key] += " " + line.strip()
            continue

        match = re.match(r'^([\w-]+):\s*(.*)$', line)
        if match:
            key, value = match.group(1), match.group(2)
            current_key = key
            headers[key] = value

    return headers


def parse_authentication_results(auth_header: str) -> dict:
    """
    Extract spf, dkim, and dmarc results (pass/fail/none/neutral)
    from an Authentication-Results header value.
    """
    results = {"spf": "none", "dkim": "none", "dmarc": "none"}

    if not auth_header:
        return results

    for protocol in results:
        match = re.search(rf'{protocol}=(\w+)', auth_header, re.IGNORECASE)
        if match:
            results[protocol] = match.group(1).lower()

    return results


def extract_display_name_and_email(from_header: str) -> tuple:
    """
    Split a From header like:
        "PayPal Security" <security@paypa1-alerts.com>
    into display name and actual email address.
    """
    match = re.match(r'^"?([^"<]*)"?\s*<([^>]+)>$', from_header.strip())
    if match:
        display_name = match.group(1).strip()
        email_address = match.group(2).strip()
        return display_name, email_address

    # No display name, just a bare email address
    return "", from_header.strip()


def check_display_name_spoofing(from_header: str) -> dict:
    """
    Check if the display name claims to be a well-known brand while
    the actual email domain is NOT that brand's real, official domain.

    Important: we check for an exact match (or a proper subdomain) of
    the official domain - not just whether the brand name appears
    somewhere in the domain string. A naive substring check would
    incorrectly clear "netflix-billing-support.com" as legitimate,
    just because it contains the word "netflix".
    """
    display_name, email_address = extract_display_name_and_email(from_header)
    display_name_lower = display_name.lower()
    domain = email_address.split("@")[-1].lower() if "@" in email_address else ""

    for brand, official_domains in COMMONLY_IMPERSONATED_BRANDS.items():
        if brand not in display_name_lower:
            continue

        is_official_domain = any(
            domain == official or domain.endswith("." + official)
            for official in official_domains
        )

        if not is_official_domain:
            return {
                "spoofed": True,
                "claimed_brand": brand,
                "actual_domain": domain,
            }

    return {"spoofed": False, "claimed_brand": None, "actual_domain": domain}


def check_reply_to_mismatch(from_header: str, reply_to_header: str) -> bool:
    """
    Flag when Reply-To points to a completely different domain than
    From. Legitimate organizations rarely do this; phishers use it so
    replies (or reply-based credential harvesting) go to them instead
    of the spoofed sender.
    """
    if not reply_to_header:
        return False

    _, from_email = extract_display_name_and_email(from_header)
    from_domain = from_email.split("@")[-1].lower() if "@" in from_email else ""

    _, reply_email = extract_display_name_and_email(reply_to_header)
    reply_domain = reply_email.split("@")[-1].lower() if "@" in reply_email else ""

    return bool(from_domain and reply_domain and from_domain != reply_domain)


def analyze_headers(raw_email: str) -> dict:
    """
    Run the full header-analysis pipeline and return authentication
    results, spoofing checks, and a header-based risk contribution.
    """
    headers = parse_headers(raw_email)

    from_header = headers.get("From", "")
    reply_to_header = headers.get("Reply-To", "")
    auth_header = headers.get("Authentication-Results", "")

    auth_results = parse_authentication_results(auth_header)
    display_spoofing = check_display_name_spoofing(from_header)
    reply_to_mismatch = check_reply_to_mismatch(from_header, reply_to_header)

    score = 0
    reasons = []

    if auth_results["spf"] == "fail":
        score += 3
        reasons.append("SPF check FAILED - sending server is not authorized for this domain")
    if auth_results["dkim"] in ("fail", "none"):
        score += 2
        reasons.append(f"DKIM check is '{auth_results['dkim']}' - message signature missing or invalid")
    if auth_results["dmarc"] == "fail":
        score += 3
        reasons.append("DMARC check FAILED - this message fails the domain's own authentication policy")

    if display_spoofing["spoofed"]:
        score += 4
        reasons.append(
            f"Display name claims to be '{display_spoofing['claimed_brand']}' "
            f"but actual domain is '{display_spoofing['actual_domain']}'"
        )

    if reply_to_mismatch:
        score += 2
        reasons.append("Reply-To domain does not match From domain")

    return {
        "headers": headers,
        "auth_results": auth_results,
        "display_spoofing": display_spoofing,
        "reply_to_mismatch": reply_to_mismatch,
        "header_score": score,
        "header_reasons": reasons,
    }
