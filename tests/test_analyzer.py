"""
test_analyzer.py
-----------------
Unit tests for analyzer.py (content-based phishing detection).
"""

import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from analyzer import (
    extract_urls,
    levenshtein_distance,
    analyze_urls,
    find_urgency_language,
    find_generic_greeting,
    find_suspicious_attachments,
    analyze_message,
)


def test_extract_urls_finds_http_links():
    text = "Visit http://example.com or https://test.org/page for more info."
    urls = extract_urls(text)
    assert len(urls) == 2, "Should find exactly 2 URLs"


def test_levenshtein_distance_identical_strings():
    assert levenshtein_distance("paypal.com", "paypal.com") == 0


def test_levenshtein_distance_one_edit():
    assert levenshtein_distance("paypa1.com", "paypal.com") == 1


def test_analyze_urls_detects_typosquatting():
    urls = ["http://paypa1.com/login"]
    findings = analyze_urls(urls)
    assert len(findings["typosquatted_domains"]) == 1, "Should flag paypa1.com as typosquatting"


def test_analyze_urls_detects_ip_based_link():
    urls = ["http://192.168.1.1/reset"]
    findings = analyze_urls(urls)
    assert len(findings["ip_based_urls"]) == 1, "Should flag raw IP address URL"


def test_analyze_urls_detects_shortener():
    urls = ["http://bit.ly/abc123"]
    findings = analyze_urls(urls)
    assert len(findings["shortened_urls"]) == 1, "Should flag known URL shortener"


def test_analyze_urls_ignores_legitimate_domain():
    urls = ["https://www.amazon.com/orders"]
    findings = analyze_urls(urls)
    assert not findings["typosquatted_domains"], "Legitimate domain should not be flagged"
    assert not findings["ip_based_urls"]
    assert not findings["shortened_urls"]


def test_find_urgency_language():
    text = "Your account will be suspended. Act now to avoid closure."
    phrases = find_urgency_language(text)
    assert len(phrases) >= 1, "Should detect at least one urgency phrase"


def test_find_generic_greeting():
    text = "Dear Customer, please review your invoice."
    greetings = find_generic_greeting(text)
    assert "dear customer" in greetings


def test_find_suspicious_attachments():
    text = "Please see the attached invoice.pdf.exe for details."
    attachments = find_suspicious_attachments(text)
    assert "invoice.pdf.exe" in attachments


def test_analyze_message_phishing_scores_high():
    text = (
        "Dear Customer, your account will be suspended. "
        "Verify now: http://paypa1.com/verify"
    )
    result = analyze_message(text)
    assert result["verdict"] in ("Suspicious", "Phishing")


def test_analyze_message_legit_scores_low():
    text = "Hi Nitin, your order has shipped. Track it at https://www.amazon.com/track"
    result = analyze_message(text)
    assert result["verdict"] == "Likely Legitimate"


def run_all_tests():
    tests = [
        test_extract_urls_finds_http_links,
        test_levenshtein_distance_identical_strings,
        test_levenshtein_distance_one_edit,
        test_analyze_urls_detects_typosquatting,
        test_analyze_urls_detects_ip_based_link,
        test_analyze_urls_detects_shortener,
        test_analyze_urls_ignores_legitimate_domain,
        test_find_urgency_language,
        test_find_generic_greeting,
        test_find_suspicious_attachments,
        test_analyze_message_phishing_scores_high,
        test_analyze_message_legit_scores_low,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            print(f"PASS: {test.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL: {test.__name__} -> {e}")
            failed += 1

    print(f"\n{passed} passed, {failed} failed out of {len(tests)} tests")


if __name__ == "__main__":
    run_all_tests()
