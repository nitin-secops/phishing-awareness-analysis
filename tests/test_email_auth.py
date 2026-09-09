"""
test_email_auth.py
-------------------
Unit tests for email_auth.py (header-based phishing detection).
"""

import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from email_auth import (
    parse_headers,
    parse_authentication_results,
    extract_display_name_and_email,
    check_display_name_spoofing,
    check_reply_to_mismatch,
    analyze_headers,
)


SAMPLE_RAW_EMAIL = """From: "PayPal Security" <security@paypa1-alerts.com>
Reply-To: attacker@totally-different-domain.ru
Subject: Urgent: Verify Your Account
Authentication-Results: mx.google.com;
    spf=fail smtp.mailfrom=paypa1-alerts.com;
    dkim=none;
    dmarc=fail header.from=paypa1-alerts.com

Dear Customer, please verify your account.
"""

LEGIT_RAW_EMAIL = """From: "Amazon.in" <no-reply@amazon.in>
Reply-To: no-reply@amazon.in
Subject: Your order has shipped
Authentication-Results: mx.google.com;
    spf=pass smtp.mailfrom=amazon.in;
    dkim=pass;
    dmarc=pass header.from=amazon.in

Hi Nitin, your order has shipped.
"""


def test_parse_headers_extracts_from():
    headers = parse_headers(SAMPLE_RAW_EMAIL)
    assert "From" in headers
    assert "paypa1-alerts.com" in headers["From"]


def test_parse_headers_handles_folded_lines():
    headers = parse_headers(SAMPLE_RAW_EMAIL)
    # Authentication-Results spans multiple lines in the raw text -
    # it should be joined into a single value.
    assert "spf=fail" in headers["Authentication-Results"]
    assert "dmarc=fail" in headers["Authentication-Results"]


def test_parse_authentication_results():
    auth_value = "spf=fail smtp.mailfrom=x.com; dkim=none; dmarc=fail header.from=x.com"
    results = parse_authentication_results(auth_value)
    assert results["spf"] == "fail"
    assert results["dkim"] == "none"
    assert results["dmarc"] == "fail"


def test_extract_display_name_and_email():
    display_name, email = extract_display_name_and_email('"PayPal Security" <security@paypa1-alerts.com>')
    assert display_name == "PayPal Security"
    assert email == "security@paypa1-alerts.com"


def test_display_name_spoofing_detected():
    result = check_display_name_spoofing('"PayPal Security" <security@paypa1-alerts.com>')
    assert result["spoofed"] is True
    assert result["claimed_brand"] == "paypal"


def test_display_name_spoofing_not_flagged_for_real_domain():
    result = check_display_name_spoofing('"Amazon.in" <no-reply@amazon.in>')
    assert result["spoofed"] is False, "amazon.in is a legitimate regional Amazon domain"


def test_display_name_spoofing_not_flagged_for_lookalike_substring():
    # This is the bug we found and fixed: a domain that merely CONTAINS
    # the brand name should not automatically be treated as legitimate.
    result = check_display_name_spoofing('"Netflix" <info@netflix-billing-support.com>')
    assert result["spoofed"] is True, "netflix-billing-support.com is not netflix.com"


def test_reply_to_mismatch_detected():
    mismatch = check_reply_to_mismatch(
        '"PayPal Security" <security@paypa1-alerts.com>',
        "attacker@totally-different-domain.ru",
    )
    assert mismatch is True


def test_reply_to_mismatch_not_flagged_when_same_domain():
    mismatch = check_reply_to_mismatch(
        '"Amazon.in" <no-reply@amazon.in>',
        "no-reply@amazon.in",
    )
    assert mismatch is False


def test_analyze_headers_phishing_email():
    result = analyze_headers(SAMPLE_RAW_EMAIL)
    assert result["header_score"] > 0
    assert result["auth_results"]["spf"] == "fail"


def test_analyze_headers_legit_email():
    result = analyze_headers(LEGIT_RAW_EMAIL)
    assert result["header_score"] == 0
    assert result["header_reasons"] == []


def run_all_tests():
    tests = [
        test_parse_headers_extracts_from,
        test_parse_headers_handles_folded_lines,
        test_parse_authentication_results,
        test_extract_display_name_and_email,
        test_display_name_spoofing_detected,
        test_display_name_spoofing_not_flagged_for_real_domain,
        test_display_name_spoofing_not_flagged_for_lookalike_substring,
        test_reply_to_mismatch_detected,
        test_reply_to_mismatch_not_flagged_when_same_domain,
        test_analyze_headers_phishing_email,
        test_analyze_headers_legit_email,
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
