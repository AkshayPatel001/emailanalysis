"""
Tests for the Header Analyzer Engine.
"""
from app.engines.header_analyzer import HeaderAnalyzer

analyzer = HeaderAnalyzer()


def test_spf_fail():
    headers = {
        "Authentication-Results": "mx.google.com; spf=fail smtp.mailfrom=test@example.com; dkim=pass; dmarc=pass",
        "From": "test@example.com",
        "To": "dest@test.com",
        "Date": "Wed, 25 Jun 2026",
        "Subject": "Test",
    }
    result = analyzer.analyze(headers, "test@example.com")
    assert result.spf is not None
    assert result.spf.result == "fail"
    assert not result.spf.is_pass
    assert result.total_risk_points > 0


def test_all_pass():
    headers = {
        "Authentication-Results": "mx.google.com; spf=pass; dkim=pass; dmarc=pass",
        "From": "legit@company.com",
        "To": "user@company.com",
        "Date": "Wed, 25 Jun 2026",
        "Subject": "Meeting",
        "Received": "from mail.company.com",
    }
    result = analyzer.analyze(headers, "legit@company.com")
    assert result.spf.is_pass
    assert result.dkim.is_pass
    assert result.dmarc.is_pass
    assert not result.sender_spoofing_detected


def test_sender_spoofing():
    headers = {
        "Authentication-Results": "mx.google.com; spf=pass; dkim=pass; dmarc=pass",
        "From": "ceo@company.com",
        "Return-Path": "<attacker@evil.com>",
        "To": "finance@company.com",
        "Date": "Wed, 25 Jun 2026",
        "Subject": "Wire Transfer",
        "Received": "from mail.evil.com",
    }
    result = analyzer.analyze(headers, "ceo@company.com", "<attacker@evil.com>")
    assert result.sender_spoofing_detected
    spoofing_findings = [f for f in result.findings if f.category == "spoofing"]
    assert len(spoofing_findings) > 0


def test_missing_headers():
    headers = {"Received": "from somewhere"}
    result = analyzer.analyze(headers)
    anomaly_findings = [f for f in result.findings if f.category == "anomaly"]
    assert len(anomaly_findings) > 0
