"""
threat_intel.py
----------------
Integrates with the VirusTotal API (v3) to check a URL's reputation
against 70+ antivirus and security vendors.

How VirusTotal's URL lookup works:
  1. A URL is identified by a special "id": the URL string, base64
     encoded (URL-safe variant, no padding).
  2. GET /api/v3/urls/{id} returns the latest analysis IF that URL
     has been scanned before by anyone.
  3. If it hasn't been scanned before (404), we can POST the URL to
     submit it for a fresh scan, then poll the analysis endpoint
     until it completes.

This module handles both cases, respects the free-tier rate limit
(4 requests/minute), and - importantly - degrades gracefully to an
"offline" result if there's no API key or no internet connection,
so the rest of the tool keeps working either way.
"""

import base64
import time

import requests

from config import get_virustotal_api_key

VT_BASE_URL = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT_SECONDS = 15
POLL_ATTEMPTS = 3
POLL_DELAY_SECONDS = 15  # free tier: max 4 requests/minute, so we space these out


def url_to_vt_id(url: str) -> str:
    """
    Convert a URL into VirusTotal's expected "id" format: URL-safe
    base64 encoding of the URL string, with '=' padding stripped.
    """
    encoded = base64.urlsafe_b64encode(url.encode()).decode()
    return encoded.strip("=")


def _headers(api_key: str) -> dict:
    return {"x-apikey": api_key}


def _interpret_stats(stats: dict) -> dict:
    """
    Turn VirusTotal's vendor vote counts into a simple verdict and a
    score contribution consistent with our other scoring modules.

    `stats` looks like: {"malicious": 8, "suspicious": 2,
                          "harmless": 60, "undetected": 5}
    """
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious >= 3:
        verdict = "Malicious"
        score = 6
    elif malicious > 0 or suspicious >= 3:
        verdict = "Suspicious"
        score = 3
    else:
        verdict = "Clean"
        score = 0

    return {
        "verdict": verdict,
        "score": score,
        "malicious_votes": malicious,
        "suspicious_votes": suspicious,
        "total_vendors": sum(stats.values()) if stats else 0,
    }


def _get_existing_report(url: str, api_key: str):
    """Try to fetch an existing analysis. Returns stats dict or None if not found."""
    url_id = url_to_vt_id(url)
    response = requests.get(
        f"{VT_BASE_URL}/urls/{url_id}",
        headers=_headers(api_key),
        timeout=REQUEST_TIMEOUT_SECONDS,
    )

    if response.status_code == 200:
        data = response.json()
        return data["data"]["attributes"]["last_analysis_stats"]

    return None  # 404 (not found) or another non-200 status


def _submit_and_poll(url: str, api_key: str):
    """Submit a new URL for scanning and poll briefly for results."""
    submit_response = requests.post(
        f"{VT_BASE_URL}/urls",
        headers=_headers(api_key),
        data={"url": url},
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    submit_response.raise_for_status()
    analysis_id = submit_response.json()["data"]["id"]

    for attempt in range(POLL_ATTEMPTS):
        time.sleep(POLL_DELAY_SECONDS)
        poll_response = requests.get(
            f"{VT_BASE_URL}/analyses/{analysis_id}",
            headers=_headers(api_key),
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        poll_response.raise_for_status()
        data = poll_response.json()["data"]

        if data["attributes"]["status"] == "completed":
            return data["attributes"]["stats"]

    return None  # gave up polling - analysis still pending


def check_url_reputation(url: str) -> dict:
    """
    Look up a URL's reputation on VirusTotal.

    Returns a dict that always has a "mode" key so callers (and the
    report generator) can tell whether this was a real lookup or an
    offline fallback:
        mode = "live"    -> real VirusTotal data used
        mode = "offline" -> no API key / no internet / API error
        mode = "pending" -> submitted for scanning, result not ready yet
    """
    api_key = get_virustotal_api_key()

    if not api_key:
        return {
            "mode": "offline",
            "verdict": "Unknown (offline)",
            "score": 0,
            "note": "No VirusTotal API key configured - skipped live lookup.",
        }

    try:
        stats = _get_existing_report(url, api_key)

        if stats is None:
            stats = _submit_and_poll(url, api_key)

        if stats is None:
            return {
                "mode": "pending",
                "verdict": "Unknown (scan pending)",
                "score": 0,
                "note": "URL was submitted to VirusTotal but analysis did not "
                        "finish within the polling window.",
            }

        result = _interpret_stats(stats)
        result["mode"] = "live"
        return result

    except requests.exceptions.RequestException as e:
        # Covers no internet, timeouts, DNS failures, bad API key, etc.
        return {
            "mode": "offline",
            "verdict": "Unknown (lookup failed)",
            "score": 0,
            "note": f"VirusTotal lookup failed, continuing in offline mode: {e}",
        }
