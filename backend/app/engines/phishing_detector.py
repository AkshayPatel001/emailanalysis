"""
Phishing Detection Engine
Detects urgency language, credential harvesting, BEC, brand impersonation,
and other phishing indicators in email subject, body, and HTML content.
"""
import logging
import re
from typing import Optional

from app.schemas import PhishingIndicator, PhishingAnalysisResult
from app.utils.sanitizer import strip_html_to_text

logger = logging.getLogger(__name__)

# ================================================================
# Detection Pattern Databases
# ================================================================

URGENCY_PATTERNS = [
    (r'\b(?:immediate(?:ly)?|urgent(?:ly)?)\b', 0.7, "Urgency language detected"),
    (r'\b(?:act\s+now|action\s+required|response\s+required)\b', 0.8, "Demand for immediate action"),
    (r'\b(?:expires?\s+(?:today|soon|in\s+\d+))\b', 0.7, "Artificial deadline pressure"),
    (r'\b(?:last\s+(?:chance|warning|notice|reminder))\b', 0.75, "Scarcity/fear tactic"),
    (r'\b(?:account\s+(?:suspended|locked|disabled|terminated|closed))\b', 0.85, "Account threat"),
    (r'\b(?:unauthorized\s+(?:access|activity|login|transaction))\b', 0.8, "Fear of unauthorized access"),
    (r'\b(?:verify\s+(?:your|the)\s+(?:account|identity|information))\b', 0.8, "Verification request"),
    (r'\b(?:failure\s+to\s+(?:respond|verify|comply|update))\b', 0.75, "Threat of consequence"),
    (r'\b(?:within\s+\d+\s+(?:hours?|minutes?|days?))\b', 0.7, "Time-limited pressure"),
    (r'\b(?:do\s+not\s+ignore|cannot\s+be\s+ignored)\b', 0.65, "Ignoring is not an option"),
]

CREDENTIAL_PATTERNS = [
    (r'\b(?:enter\s+(?:your\s+)?(?:password|credentials|login))\b', 0.9, "Password solicitation"),
    (r'\b(?:confirm\s+(?:your\s+)?(?:identity|password|account|details))\b', 0.85, "Identity confirmation request"),
    (r'\b(?:update\s+(?:your\s+)?(?:payment|billing|card)\s+(?:info|information|details))\b', 0.9, "Payment info request"),
    (r'\b(?:(?:re-?)?(?:validate|authenticate|verify)\s+(?:your\s+)?(?:account|credentials))\b', 0.85, "Account validation request"),
    (r'\b(?:social\s+security|ssn|tax\s+id)\b', 0.95, "SSN/tax ID request — highly suspicious"),
    (r'\b(?:click\s+(?:here|below|the\s+link)\s+to\s+(?:verify|confirm|update|login|sign\s+in))\b', 0.85, "Directed click action"),
    (r'\b(?:log\s*in\s+to\s+(?:your|the)\s+account)\b', 0.7, "Login prompt in email body"),
]

BEC_PATTERNS = [
    (r'\b(?:wire\s+transfer|bank\s+transfer|direct\s+deposit)\b', 0.85, "Wire transfer request"),
    (r'\b(?:gift\s+cards?|itunes\s+cards?|google\s+play\s+cards?)\b', 0.9, "Gift card request — classic BEC"),
    (r'\b(?:purchase\s+(?:gift\s+cards?|bitcoin|cryptocurrency))\b', 0.9, "Purchase request for untraceable items"),
    (r'\b(?:(?:ceo|cfo|president|director)\s+(?:asked|requested|needs))\b', 0.8, "Authority impersonation"),
    (r'\b(?:keep\s+this\s+(?:confidential|between\s+us|private|quiet))\b', 0.85, "Secrecy request"),
    (r'\b(?:i\s+need\s+(?:a\s+)?favor|can\s+you\s+help\s+me\s+with\s+(?:something|a\s+task))\b', 0.7, "Personal favor request"),
    (r'\b(?:change\s+(?:the\s+)?(?:bank|account|payment)\s+(?:details|information))\b', 0.85, "Payment redirect attempt"),
    (r'\b(?:invoice|payment|overdue|outstanding\s+balance)\b', 0.6, "Invoice/payment language"),
]

BRAND_TARGETS = [
    "microsoft", "office365", "outlook", "google", "gmail", "apple", "icloud",
    "amazon", "paypal", "netflix", "facebook", "instagram", "whatsapp",
    "linkedin", "twitter", "dropbox", "docusign", "adobe", "chase",
    "wellsfargo", "bankofamerica", "citibank", "usps", "fedex", "ups", "dhl",
]


class PhishingDetector:
    """Detects phishing indicators in email content."""

    def analyze(self, subject: Optional[str] = None, body_text: Optional[str] = None,
                body_html: Optional[str] = None, sender_email: Optional[str] = None,
                sender_name: Optional[str] = None) -> PhishingAnalysisResult:
        logger.info("Running phishing detection", extra={"engine": "phishing_detector"})

        indicators = []
        combined_text = ""
        if subject:
            combined_text += subject + " "
        if body_text:
            combined_text += body_text + " "
        if body_html:
            combined_text += strip_html_to_text(body_html)

        if not combined_text.strip():
            return PhishingAnalysisResult()

        # Run detection categories
        indicators.extend(self._check_patterns(combined_text, URGENCY_PATTERNS, "urgency"))
        indicators.extend(self._check_patterns(combined_text, CREDENTIAL_PATTERNS, "credential_harvest"))
        indicators.extend(self._check_patterns(combined_text, BEC_PATTERNS, "bec"))
        indicators.extend(self._check_brand_impersonation(combined_text, sender_email, sender_name))

        if body_html:
            indicators.extend(self._check_html_threats(body_html))

        if subject:
            indicators.extend(self._check_subject_spoofing(subject))

        # Calculate overall confidence
        if indicators:
            max_conf = max(i.confidence for i in indicators)
            avg_conf = sum(i.confidence for i in indicators) / len(indicators)
            overall = min(1.0, (max_conf * 0.6) + (avg_conf * 0.3) + (min(len(indicators), 5) / 5 * 0.1))
        else:
            overall = 0.0

        total_risk = sum(self._confidence_to_points(i.confidence) for i in indicators)

        return PhishingAnalysisResult(
            indicators=indicators,
            overall_confidence=round(overall, 2),
            is_likely_phishing=overall >= 0.6,
            total_risk_points=min(total_risk, 50),
        )

    def _check_patterns(self, text: str, patterns: list, category: str) -> list[PhishingIndicator]:
        results = []
        text_lower = text.lower()
        for pattern, confidence, explanation in patterns:
            match = re.search(pattern, text_lower, re.IGNORECASE)
            if match:
                severity = "critical" if confidence >= 0.9 else "high" if confidence >= 0.75 else "medium"
                results.append(PhishingIndicator(
                    category=category, indicator=explanation,
                    evidence=match.group(0)[:100], confidence=confidence,
                    severity=severity, explanation=explanation,
                ))
        return results

    def _check_brand_impersonation(self, text: str, sender_email: Optional[str],
                                    sender_name: Optional[str]) -> list[PhishingIndicator]:
        results = []
        text_lower = text.lower()
        check_fields = (sender_email or "").lower() + " " + (sender_name or "").lower()

        for brand in BRAND_TARGETS:
            if brand in text_lower or brand in check_fields:
                # Check if sender domain actually matches the brand
                if sender_email and brand not in sender_email.lower():
                    results.append(PhishingIndicator(
                        category="brand_impersonation",
                        indicator=f"Possible {brand.title()} impersonation",
                        evidence=f"Brand '{brand}' mentioned but sender is {sender_email}",
                        confidence=0.75, severity="high",
                        explanation=f"Email references {brand.title()} but sender domain doesn't match.",
                    ))
                    break  # One brand impersonation finding is enough
        return results

    def _check_html_threats(self, html: str) -> list[PhishingIndicator]:
        results = []
        html_lower = html.lower()

        # Hidden form actions
        form_match = re.search(r'<form[^>]+action=["\']([^"\']+)', html_lower)
        if form_match:
            results.append(PhishingIndicator(
                category="credential_harvest", indicator="HTML form with external action",
                evidence=form_match.group(1)[:100], confidence=0.85, severity="high",
                explanation="Email contains an HTML form — likely credential harvesting.",
            ))

        # Data URIs (can hide malicious content)
        if "data:" in html_lower and "base64" in html_lower:
            results.append(PhishingIndicator(
                category="evasion", indicator="Base64 data URI detected",
                evidence="data:...base64", confidence=0.7, severity="medium",
                explanation="Base64 data URIs can hide malicious content from scanners.",
            ))

        # Obfuscated JavaScript
        if re.search(r'<script[^>]*>', html_lower):
            results.append(PhishingIndicator(
                category="evasion", indicator="JavaScript in email HTML",
                evidence="<script> tag detected", confidence=0.9, severity="critical",
                explanation="JavaScript in emails is almost always malicious.",
            ))

        # Hidden elements with display:none containing links
        if re.search(r'display\s*:\s*none.*?<a\s', html_lower, re.DOTALL):
            results.append(PhishingIndicator(
                category="evasion", indicator="Hidden links detected",
                evidence="display:none with anchor tags", confidence=0.75, severity="high",
                explanation="Hidden links may redirect users to malicious sites.",
            ))

        return results

    def _check_subject_spoofing(self, subject: str) -> list[PhishingIndicator]:
        results = []
        # Fake RE:/FW: to appear as conversation
        if re.match(r'^(?:RE|FW|FWD)\s*:\s*(?:RE|FW|FWD)\s*:', subject, re.IGNORECASE):
            results.append(PhishingIndicator(
                category="evasion", indicator="Multiple RE:/FW: prefixes",
                evidence=subject[:60], confidence=0.6, severity="medium",
                explanation="Stacked reply/forward prefixes often used to fake conversation history.",
            ))
        return results

    @staticmethod
    def _confidence_to_points(confidence: float) -> int:
        if confidence >= 0.9:
            return 15
        elif confidence >= 0.75:
            return 10
        elif confidence >= 0.6:
            return 7
        return 3
