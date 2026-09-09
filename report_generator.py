"""
report_generator.py
--------------------
Combines results from analyzer.py, email_auth.py, and threat_intel.py
into a single, structured report - written the way a real SOC L1
analyst would document a phishing investigation ticket.

A real SOC report always answers three questions:
  1. What did you find? (evidence / IOCs)
  2. Why does it matter? (explanation)
  3. What should be done about it? (recommended action)
"""

from analyzer import analyze_message
from email_auth import analyze_headers
from threat_intel import check_url_reputation


def combine_findings(raw_email: str) -> dict:
    """
    Run all three analysis modules on a raw email and combine their
    scores and reasons into one unified result.
    """
    content_result = analyze_message(raw_email)
    header_result = analyze_headers(raw_email)

    # Look up reputation for each URL found in the message body.
    # In offline mode (no API key / no internet) this safely returns
    # a "mode: offline" result for each URL without crashing.
    url_reputations = []
    for url in content_result["urls_found"]:
        reputation = check_url_reputation(url)
        reputation["url"] = url
        url_reputations.append(reputation)

    threat_intel_score = sum(r.get("score", 0) for r in url_reputations)

    total_score = content_result["score"] + header_result["header_score"] + threat_intel_score

    if total_score >= 10:
        final_verdict = "Phishing"
        recommended_action = (
            "Block sender domain, quarantine similar messages, and notify "
            "affected users. Escalate to Tier 2 if user reports credential "
            "entry or financial loss."
        )
    elif total_score >= 5:
        final_verdict = "Suspicious"
        recommended_action = (
            "Hold message for further review. Contact the claimed sender "
            "through a verified channel (not by replying) before trusting "
            "any links or requests inside it."
        )
    else:
        final_verdict = "Likely Legitimate"
        recommended_action = (
            "No action required. Continue standard monitoring."
        )

    return {
        "total_score": total_score,
        "final_verdict": final_verdict,
        "recommended_action": recommended_action,
        "content_findings": content_result,
        "header_findings": header_result,
        "url_reputations": url_reputations,
    }


def generate_report(raw_email: str, case_id: str = "N/A") -> str:
    """
    Produce a human-readable, SOC-ticket-style report as a string,
    ready to print to the console or save to a file.
    """
    result = combine_findings(raw_email)

    lines = []
    lines.append("=" * 60)
    lines.append(f"PHISHING ANALYSIS REPORT - Case #{case_id}")
    lines.append("=" * 60)
    lines.append(f"Final Verdict : {result['final_verdict']}")
    lines.append(f"Total Risk Score : {result['total_score']}")
    lines.append("")

    lines.append("--- Header / Authentication Findings ---")
    if result["header_findings"]["header_reasons"]:
        for reason in result["header_findings"]["header_reasons"]:
            lines.append(f"  [!] {reason}")
    else:
        lines.append("  No header-based red flags found.")
    lines.append("")

    lines.append("--- Content Findings ---")
    if result["content_findings"]["reasons"]:
        for reason in result["content_findings"]["reasons"]:
            lines.append(f"  [!] {reason}")
    else:
        lines.append("  No content-based red flags found.")
    lines.append("")

    lines.append("--- URL Threat Intelligence (VirusTotal) ---")
    if result["url_reputations"]:
        for rep in result["url_reputations"]:
            lines.append(f"  URL: {rep['url']}")
            lines.append(f"    Mode: {rep['mode']} | Verdict: {rep['verdict']}")
            if "note" in rep:
                lines.append(f"    Note: {rep['note']}")
    else:
        lines.append("  No URLs found in message.")
    lines.append("")

    lines.append("--- Recommended Action ---")
    lines.append(f"  {result['recommended_action']}")
    lines.append("=" * 60)

    return "\n".join(lines)
