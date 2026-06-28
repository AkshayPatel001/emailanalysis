"""
Email Header Analyzer Engine
Analyzes SPF, DKIM, DMARC, ARC results, sender spoofing, and header anomalies.
"""
import logging
import re
from typing import Optional

from app.schemas import AuthResult, HeaderFinding, HeaderAnalysisResult

logger = logging.getLogger(__name__)


class HeaderAnalyzer:
    """Analyzes email headers for auth results, spoofing, and anomalies."""

    def analyze(self, headers: dict[str, str], sender_email: Optional[str] = None,
                return_path: Optional[str] = None, reply_to: Optional[str] = None) -> HeaderAnalysisResult:
        logger.info("Running header analysis", extra={"engine": "header_analyzer"})
        findings = []
        total_risk = 0

        spf = self._parse_auth(headers, "spf")
        dkim = self._parse_auth(headers, "dkim")
        dmarc = self._parse_auth(headers, "dmarc")
        arc = self._parse_arc(headers)

        for auth, name in [(spf, "SPF"), (dkim, "DKIM"), (dmarc, "DMARC")]:
            if auth is None:
                sev = "medium" if name != "DMARC" else "low"
                pts = 10 if name != "DMARC" else 5
                findings.append(HeaderFinding(category="authentication", title=f"{name} Not Present",
                    description=f"No {name} result found in headers.", severity=sev, risk_points=pts))
                total_risk += pts
            elif not auth.is_pass:
                pts = 20 if auth.result == "fail" else 10
                findings.append(HeaderFinding(category="authentication", title=f"{name} {auth.result.upper()}",
                    description=f"{name} returned '{auth.result}'. {auth.detail or ''}", severity="high", risk_points=pts))
                total_risk += pts
            else:
                findings.append(HeaderFinding(category="authentication", title=f"{name} PASS",
                    description=f"{name} passed. {auth.detail or ''}", severity="info", risk_points=0))

        spoofing = False
        if sender_email:
            sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else None
            for label, value in [("Return-Path", return_path), ("Reply-To", reply_to)]:
                if value and sender_domain:
                    other_email = re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', value.strip("<>"))
                    if other_email:
                        other_domain = other_email.group(0).split("@")[-1].lower()
                        if other_domain != sender_domain:
                            findings.append(HeaderFinding(category="spoofing",
                                title=f"From / {label} Domain Mismatch",
                                description=f"From domain '{sender_domain}' ≠ {label} domain '{other_domain}'.",
                                severity="high", risk_points=15))
                            total_risk += 15
                            spoofing = True

        # X-Mailer check
        x_mailer = self._get_header(headers, "X-Mailer")
        if x_mailer and any(s in x_mailer.lower() for s in ["phpmailer", "swiftmailer"]):
            findings.append(HeaderFinding(category="spoofing", title=f"Bulk Mailer: {x_mailer}",
                description="Sent via bulk/programmatic mailing tool.", severity="medium", risk_points=5))
            total_risk += 5

        # Missing headers
        missing = [h for h in ["From", "To", "Date", "Subject"] if not self._get_header(headers, h)]
        if missing:
            findings.append(HeaderFinding(category="anomaly", title="Missing Critical Headers",
                description=f"Missing: {', '.join(missing)}", severity="medium", risk_points=10))
            total_risk += 10

        # Received header count
        rx_count = sum(1 for k in headers if k.lower() == "received")
        if rx_count == 0:
            findings.append(HeaderFinding(category="anomaly", title="No Received Headers",
                description="No Received headers found — possible forgery.", severity="high", risk_points=15))
            total_risk += 15

        # Spam flags
        for key in headers:
            if "x-spam" in key.lower():
                val = headers[key]
                if any(w in val.lower() for w in ["yes", "high", "spam"]):
                    findings.append(HeaderFinding(category="anomaly", title="Spam Flag Detected",
                        description=f"{key}: {val[:200]}", severity="medium", risk_points=10))
                    total_risk += 10
                    break

        return HeaderAnalysisResult(spf=spf, dkim=dkim, dmarc=dmarc, arc=arc,
            findings=findings, sender_spoofing_detected=spoofing, total_risk_points=total_risk)

    def _parse_auth(self, headers: dict, mechanism: str) -> Optional[AuthResult]:
        auth_results = self._get_header(headers, "Authentication-Results")
        if not auth_results:
            if mechanism == "spf":
                rx_spf = self._get_header(headers, "Received-SPF")
                if rx_spf:
                    m = re.match(r'(\w+)', rx_spf)
                    if m:
                        r = m.group(1).lower()
                        return AuthResult(mechanism="spf", result=r, detail=rx_spf[:200], is_pass=r == "pass")
            return None
        m = re.search(rf'{mechanism}=(\w+)', auth_results, re.IGNORECASE)
        if m:
            r = m.group(1).lower()
            detail_m = re.search(rf'{mechanism}=\w+\s+\(([^)]+)\)', auth_results, re.IGNORECASE)
            detail = detail_m.group(1) if detail_m else None
            return AuthResult(mechanism=mechanism, result=r, detail=detail, is_pass=r == "pass")
        return None

    def _parse_arc(self, headers: dict) -> Optional[AuthResult]:
        arc = self._get_header(headers, "ARC-Authentication-Results")
        if not arc:
            arc = self._get_header(headers, "ARC-Seal")
        if arc:
            m = re.search(r'(?:arc|cv)=(\w+)', arc, re.IGNORECASE)
            r = m.group(1).lower() if m else "none"
            return AuthResult(mechanism="arc", result=r, detail=arc[:200], is_pass=r == "pass")
        return None

    @staticmethod
    def _get_header(headers: dict, name: str) -> Optional[str]:
        for k, v in headers.items():
            if k.lower() == name.lower():
                return v
        return None
