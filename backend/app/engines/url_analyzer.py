"""
URL Analysis Engine
Extracts and analyzes URLs for suspicious TLDs, shorteners, punycode,
typosquatting, and redirect chains.
"""
import logging
import re
from typing import Optional
from urllib.parse import urlparse

from app.schemas import UrlFinding, UrlAnalysisResult

logger = logging.getLogger(__name__)

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz", ".club",
    ".work", ".click", ".link", ".info", ".icu", ".cam", ".rest", ".surf",
    ".monster", ".quest", ".cfd", ".sbs",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "shorturl.at", "cutt.ly", "tiny.cc",
    "lnkd.in", "rb.gy", "qr.ae", "v.gd", "clck.ru",
}

# Top brands for typosquatting detection
BRAND_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
    "facebook.com", "netflix.com", "linkedin.com", "twitter.com", "instagram.com",
    "dropbox.com", "chase.com", "wellsfargo.com", "bankofamerica.com",
    "outlook.com", "office365.com", "docusign.com", "adobe.com",
}

URL_REGEX = re.compile(
    r'https?://[^\s<>"\')\]]+|'
    r'(?:www\.)[^\s<>"\')\]]+',
    re.IGNORECASE,
)

# Also match defanged URLs
DEFANGED_URL_REGEX = re.compile(
    r'hxxps?://[^\s<>"\')\]]+|'
    r'https?\[://\][^\s<>"\')\]]+',
    re.IGNORECASE,
)


class UrlAnalyzer:
    """Extracts and analyzes URLs from email content."""

    def analyze(self, body_text: Optional[str] = None, body_html: Optional[str] = None) -> UrlAnalysisResult:
        logger.info("Running URL analysis", extra={"engine": "url_analyzer"})

        combined = ""
        if body_text:
            combined += body_text + " "
        if body_html:
            combined += body_html

        # Also extract href attributes from HTML
        if body_html:
            href_matches = re.findall(r'href=["\']([^"\']+)', body_html, re.IGNORECASE)
            combined += " " + " ".join(href_matches)

        urls = self._extract_urls(combined)
        if not urls:
            return UrlAnalysisResult()

        findings = []
        malicious = 0
        suspicious = 0
        total_risk = 0

        for url in urls:
            finding = self._analyze_single_url(url)
            findings.append(finding)
            total_risk += finding.risk_points
            if finding.reputation == "malicious":
                malicious += 1
            elif finding.reputation == "suspicious":
                suspicious += 1

        return UrlAnalysisResult(
            urls_found=len(findings), urls=findings,
            malicious_count=malicious, suspicious_count=suspicious,
            total_risk_points=min(total_risk, 60),
        )

    def _extract_urls(self, text: str) -> list[str]:
        urls = set()
        for match in URL_REGEX.finditer(text):
            url = match.group(0).rstrip(".,;:!?)")
            urls.add(url)
        for match in DEFANGED_URL_REGEX.finditer(text):
            url = match.group(0).replace("hxxp", "http").replace("[://]", "://")
            url = url.rstrip(".,;:!?)")
            urls.add(url)
        return list(urls)[:50]  # Cap at 50 URLs

    def _analyze_single_url(self, url: str) -> UrlFinding:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        domain = parsed.hostname or ""
        tld = self._get_tld(domain)

        is_https = parsed.scheme == "https"
        is_shortened = domain.lower() in URL_SHORTENERS
        is_punycode = domain.startswith("xn--") or any(p.startswith("xn--") for p in domain.split("."))
        suspicious_tld = f".{tld}" in SUSPICIOUS_TLDS if tld else False
        is_typosquat, target = self._check_typosquat(domain)

        # Calculate risk
        risk_points = 0
        reputation = "unknown"
        risk_level = "safe"

        if is_punycode:
            risk_points += 20
        if suspicious_tld:
            risk_points += 15
        if is_shortened:
            risk_points += 10
        if is_typosquat:
            risk_points += 25
        if not is_https:
            risk_points += 5
        # IP address as hostname
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            risk_points += 15

        if risk_points >= 30:
            reputation = "malicious"
            risk_level = "critical"
        elif risk_points >= 15:
            reputation = "suspicious"
            risk_level = "medium"
        else:
            reputation = "clean"
            risk_level = "safe"

        return UrlFinding(
            url=url, domain=domain, is_https=is_https,
            is_shortened=is_shortened, is_punycode=is_punycode,
            is_typosquat=is_typosquat, typosquat_target=target,
            suspicious_tld=suspicious_tld, tld=tld,
            reputation=reputation, risk_level=risk_level, risk_points=risk_points,
        )

    def _check_typosquat(self, domain: str) -> tuple[bool, Optional[str]]:
        """Check if domain is a typosquat of known brands using edit distance."""
        domain_base = domain.split(".")[0].lower()
        for brand in BRAND_DOMAINS:
            brand_base = brand.split(".")[0].lower()
            if domain_base == brand_base:
                continue  # Exact match, not typosquat
            dist = self._levenshtein(domain_base, brand_base)
            if 0 < dist <= 2 and len(domain_base) >= 4:
                return True, brand
            # Check for brand name embedded with extra chars
            if brand_base in domain_base and domain_base != brand_base:
                return True, brand
        return False, None

    @staticmethod
    def _levenshtein(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return UrlAnalyzer._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]

    @staticmethod
    def _get_tld(domain: str) -> Optional[str]:
        parts = domain.rsplit(".", 1)
        return parts[-1] if len(parts) > 1 else None
