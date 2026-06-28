"""
MITRE ATT&CK Mapper
Maps detected email threat indicators to MITRE ATT&CK techniques.
"""
import logging
from typing import Optional

from app.schemas import (
    MitreMapping, PhishingAnalysisResult, UrlAnalysisResult,
    AttachmentAnalysisResult, HeaderAnalysisResult,
)

logger = logging.getLogger(__name__)

# MITRE ATT&CK technique definitions relevant to email-based attacks
TECHNIQUE_DB = {
    "T1566.001": {
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Adversary sends spearphishing email with malicious attachment to gain access.",
    },
    "T1566.002": {
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversary sends spearphishing email with malicious link to gain access.",
    },
    "T1566.003": {
        "name": "Phishing: Spearphishing via Service",
        "tactic": "Initial Access",
        "description": "Adversary uses third-party services to send spearphishing messages.",
    },
    "T1534": {
        "name": "Internal Spearphishing",
        "tactic": "Lateral Movement",
        "description": "Adversary uses compromised internal email to phish other employees.",
    },
    "T1598": {
        "name": "Phishing for Information",
        "tactic": "Reconnaissance",
        "description": "Adversary sends phishing messages to gather victim information.",
    },
    "T1598.003": {
        "name": "Phishing for Information: Spearphishing Link",
        "tactic": "Reconnaissance",
        "description": "Adversary sends targeted phishing with links to harvest credentials.",
    },
    "T1204.001": {
        "name": "User Execution: Malicious Link",
        "tactic": "Execution",
        "description": "Adversary relies on user clicking malicious link to execute code.",
    },
    "T1204.002": {
        "name": "User Execution: Malicious File",
        "tactic": "Execution",
        "description": "Adversary relies on user opening malicious file to execute code.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "description": "Adversary uses stolen credentials to access victim systems.",
    },
    "T1114": {
        "name": "Email Collection",
        "tactic": "Collection",
        "description": "Adversary collects email data from compromised accounts.",
    },
    "T1656": {
        "name": "Impersonation",
        "tactic": "Defense Evasion",
        "description": "Adversary impersonates trusted entity to deceive victims.",
    },
}


class MitreMapper:
    """Maps email analysis findings to MITRE ATT&CK techniques."""

    def map(
        self,
        header_result: Optional[HeaderAnalysisResult] = None,
        phishing_result: Optional[PhishingAnalysisResult] = None,
        url_result: Optional[UrlAnalysisResult] = None,
        attachment_result: Optional[AttachmentAnalysisResult] = None,
    ) -> list[MitreMapping]:
        logger.info("Mapping to MITRE ATT&CK", extra={"engine": "mitre_mapper"})
        mappings = []

        # Malicious attachments -> T1566.001, T1204.002
        if attachment_result and attachment_result.suspicious_count > 0:
            mappings.append(self._build("T1566.001", 0.85, "Suspicious attachment(s) detected"))
            mappings.append(self._build("T1204.002", 0.8, "Malicious file requires user execution"))

        # Malicious URLs -> T1566.002, T1204.001
        if url_result and (url_result.malicious_count > 0 or url_result.suspicious_count > 0):
            mappings.append(self._build("T1566.002", 0.85, "Suspicious/malicious URLs detected"))
            mappings.append(self._build("T1204.001", 0.8, "Malicious link requires user click"))

        # Credential harvesting -> T1598, T1598.003
        if phishing_result:
            cred_indicators = [i for i in phishing_result.indicators if i.category == "credential_harvest"]
            if cred_indicators:
                mappings.append(self._build("T1598", 0.9, "Credential harvesting indicators found"))
                mappings.append(self._build("T1598.003", 0.85, "Phishing link for credential harvesting"))
                mappings.append(self._build("T1078", 0.7, "Stolen credentials enable account access"))

            # BEC -> T1656
            bec_indicators = [i for i in phishing_result.indicators if i.category == "bec"]
            if bec_indicators:
                mappings.append(self._build("T1656", 0.85, "Business Email Compromise / impersonation"))

            # Brand impersonation -> T1656
            brand_indicators = [i for i in phishing_result.indicators if i.category == "brand_impersonation"]
            if brand_indicators:
                mappings.append(self._build("T1656", 0.8, "Brand impersonation detected"))

        # Sender spoofing -> T1656
        if header_result and header_result.sender_spoofing_detected:
            mappings.append(self._build("T1656", 0.75, "Sender address spoofing detected"))

        # Deduplicate by technique_id, keeping highest confidence
        seen = {}
        for m in mappings:
            if m.technique_id not in seen or m.confidence > seen[m.technique_id].confidence:
                seen[m.technique_id] = m
        return list(seen.values())

    def _build(self, technique_id: str, confidence: float, evidence: str) -> MitreMapping:
        tech = TECHNIQUE_DB.get(technique_id, {})
        return MitreMapping(
            technique_id=technique_id,
            technique_name=tech.get("name", "Unknown"),
            tactic=tech.get("tactic", "Unknown"),
            description=tech.get("description", ""),
            confidence=confidence,
            evidence=evidence,
        )
