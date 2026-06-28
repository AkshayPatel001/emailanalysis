"""
Risk Scoring Engine
Aggregates findings from all analysis engines into a normalized 0-100 risk score.
"""
import logging

from app.schemas import (
    HeaderAnalysisResult, PhishingAnalysisResult, UrlAnalysisResult,
    AttachmentAnalysisResult, RiskBreakdown, RiskScoringResult,
)
from app.engines.yara_engine import YaraScanResult
from app.config import settings

logger = logging.getLogger(__name__)


class RiskScorer:
    """Calculates overall email risk score from individual engine results."""

    def score(
        self,
        header_result: HeaderAnalysisResult = None,
        phishing_result: PhishingAnalysisResult = None,
        url_result: UrlAnalysisResult = None,
        attachment_result: AttachmentAnalysisResult = None,
        yara_result: YaraScanResult = None,
    ) -> RiskScoringResult:
        logger.info("Calculating risk score", extra={"engine": "risk_scorer"})

        breakdown = []
        total_raw = 0

        # Header analysis contribution
        if header_result:
            pts = min(header_result.total_risk_points, settings.weight_header_anomaly + settings.weight_auth_failure)
            breakdown.append(RiskBreakdown(
                category="Email Authentication",
                points=pts,
                max_points=settings.weight_header_anomaly + settings.weight_auth_failure,
                description=f"{len(header_result.findings)} header findings. "
                            f"{'Spoofing detected!' if header_result.sender_spoofing_detected else 'No spoofing detected.'}",
            ))
            total_raw += pts

            if header_result.sender_spoofing_detected:
                breakdown.append(RiskBreakdown(
                    category="Sender Spoofing",
                    points=settings.weight_sender_spoof,
                    max_points=settings.weight_sender_spoof,
                    description="From/Return-Path/Reply-To domain mismatch detected.",
                ))
                total_raw += settings.weight_sender_spoof

        # Phishing analysis contribution
        if phishing_result and phishing_result.indicators:
            pts = min(phishing_result.total_risk_points, settings.weight_phishing_keywords + settings.weight_bec_indicators)
            has_bec = any(i.category == "bec" for i in phishing_result.indicators)
            has_brand = any(i.category == "brand_impersonation" for i in phishing_result.indicators)

            breakdown.append(RiskBreakdown(
                category="Phishing Indicators",
                points=min(pts, settings.weight_phishing_keywords),
                max_points=settings.weight_phishing_keywords,
                description=f"{len(phishing_result.indicators)} phishing indicators detected. "
                            f"Overall confidence: {phishing_result.overall_confidence:.0%}",
            ))
            total_raw += min(pts, settings.weight_phishing_keywords)

            if has_bec:
                breakdown.append(RiskBreakdown(
                    category="BEC Indicators",
                    points=settings.weight_bec_indicators,
                    max_points=settings.weight_bec_indicators,
                    description="Business Email Compromise indicators detected.",
                ))
                total_raw += settings.weight_bec_indicators

            if has_brand:
                breakdown.append(RiskBreakdown(
                    category="Brand Impersonation",
                    points=settings.weight_brand_impersonation,
                    max_points=settings.weight_brand_impersonation,
                    description="Possible brand impersonation detected.",
                ))
                total_raw += settings.weight_brand_impersonation

        # URL analysis contribution
        if url_result and url_result.urls_found > 0:
            pts = min(url_result.total_risk_points, settings.weight_malicious_url)
            breakdown.append(RiskBreakdown(
                category="URL Analysis",
                points=pts,
                max_points=settings.weight_malicious_url,
                description=f"{url_result.urls_found} URLs analyzed. "
                            f"{url_result.malicious_count} malicious, {url_result.suspicious_count} suspicious.",
            ))
            total_raw += pts

        # Attachment analysis contribution
        if attachment_result and attachment_result.attachment_count > 0:
            pts = min(attachment_result.total_risk_points, settings.weight_suspicious_attachment)
            breakdown.append(RiskBreakdown(
                category="Attachment Analysis",
                points=pts,
                max_points=settings.weight_suspicious_attachment,
                description=f"{attachment_result.attachment_count} attachments analyzed. "
                            f"{attachment_result.suspicious_count} suspicious.",
            ))
            total_raw += pts

        # YARA analysis contribution
        if yara_result and yara_result.total_matches > 0:
            pts = settings.weight_yara_match
            breakdown.append(RiskBreakdown(
                category="YARA Rules",
                points=pts,
                max_points=settings.weight_yara_match,
                description=f"{yara_result.total_matches} custom YARA rule matches detected.",
            ))
            total_raw += pts

        # Normalize to 0-100
        max_possible = (
            settings.weight_header_anomaly + settings.weight_auth_failure +
            settings.weight_sender_spoof + settings.weight_phishing_keywords +
            settings.weight_bec_indicators + settings.weight_brand_impersonation +
            settings.weight_malicious_url + settings.weight_suspicious_attachment +
            settings.weight_yara_match
        )
        overall_score = min(100.0, round((total_raw / max_possible) * 100, 1)) if max_possible > 0 else 0.0

        # Determine verdict and severity
        if overall_score >= 61:
            verdict = "malicious"
            severity = "critical" if overall_score >= 80 else "high"
        elif overall_score >= 26:
            verdict = "suspicious"
            severity = "high" if overall_score >= 50 else "medium"
        else:
            verdict = "clean"
            severity = "low" if overall_score >= 10 else "safe"

        return RiskScoringResult(
            overall_score=overall_score, verdict=verdict,
            severity=severity, breakdown=breakdown,
        )
