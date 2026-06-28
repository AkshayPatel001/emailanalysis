"""
Tests for the Phishing Detection Engine.
"""
from app.engines.phishing_detector import PhishingDetector

detector = PhishingDetector()


def test_urgency_detection():
    result = detector.analyze(
        subject="URGENT: Your account has been suspended",
        body_text="Immediate action required. Verify your account within 24 hours or it will be permanently closed.",
    )
    assert len(result.indicators) > 0
    assert result.overall_confidence > 0.5
    urgency = [i for i in result.indicators if i.category == "urgency"]
    assert len(urgency) > 0


def test_credential_harvesting():
    result = detector.analyze(
        body_text="Please enter your password to confirm your identity. Click here to verify your account credentials.",
    )
    cred = [i for i in result.indicators if i.category == "credential_harvest"]
    assert len(cred) > 0


def test_bec_detection():
    result = detector.analyze(
        subject="Quick favor needed",
        body_text="I need you to purchase some gift cards for a client. Keep this confidential. Wire transfer the remaining balance.",
    )
    bec = [i for i in result.indicators if i.category == "bec"]
    assert len(bec) > 0


def test_brand_impersonation():
    result = detector.analyze(
        body_text="Your Microsoft account needs verification.",
        sender_email="support@micros0ft-security.tk",
    )
    brand = [i for i in result.indicators if i.category == "brand_impersonation"]
    assert len(brand) > 0


def test_clean_email():
    result = detector.analyze(
        subject="Meeting tomorrow at 3pm",
        body_text="Hi team, just a reminder about our standup meeting tomorrow. See you there!",
        sender_email="colleague@company.com",
    )
    assert result.overall_confidence < 0.5
    assert not result.is_likely_phishing


def test_html_script_detection():
    result = detector.analyze(
        body_html='<html><script>alert("xss")</script><p>Hello</p></html>',
    )
    evasion = [i for i in result.indicators if i.category == "evasion"]
    assert len(evasion) > 0


def test_subject_spoofing():
    result = detector.analyze(subject="RE: RE: FW: Important Document")
    spoofed = [i for i in result.indicators if "RE:" in (i.evidence or "")]
    assert len(spoofed) > 0
