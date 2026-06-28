"""
Tests for the URL Analysis Engine.
"""
from app.engines.url_analyzer import UrlAnalyzer

analyzer = UrlAnalyzer()


def test_suspicious_tld():
    result = analyzer.analyze(body_text="Visit http://login-paypal.xyz/verify")
    assert result.urls_found > 0
    url = result.urls[0]
    assert url.suspicious_tld


def test_url_shortener():
    result = analyzer.analyze(body_text="Click: https://bit.ly/abc123")
    assert result.urls_found > 0
    assert result.urls[0].is_shortened


def test_typosquatting():
    result = analyzer.analyze(body_text="https://micros0ft.com/login")
    assert result.urls_found > 0
    assert result.urls[0].is_typosquat


def test_https_detection():
    result = analyzer.analyze(body_text="http://insecure-site.com/login")
    assert not result.urls[0].is_https


def test_clean_url():
    result = analyzer.analyze(body_text="Visit https://www.google.com for more info")
    assert result.urls_found > 0
    url = result.urls[0]
    assert url.is_https
    assert url.reputation == "clean"


def test_multiple_urls():
    result = analyzer.analyze(
        body_text="Link1: http://evil.tk/phish Link2: https://bit.ly/x Link3: https://google.com"
    )
    assert result.urls_found == 3


def test_ip_as_url():
    result = analyzer.analyze(body_text="http://192.168.1.1/login")
    assert result.urls_found > 0
