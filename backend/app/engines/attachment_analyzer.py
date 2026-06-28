"""
Attachment Analysis Engine
Analyzes file attachments for dangerous types, macros, scripts, and double extensions.
"""
import hashlib
import logging
from typing import Optional

from app.schemas import AttachmentFinding, AttachmentAnalysisResult
from app.utils.validators import classify_file_extension, humanize_bytes

logger = logging.getLogger(__name__)


class AttachmentAnalyzer:
    """Analyzes email attachments for security risks."""

    def analyze(self, attachments: list[AttachmentFinding]) -> AttachmentAnalysisResult:
        logger.info(f"Analyzing {len(attachments)} attachments", extra={"engine": "attachment_analyzer"})

        if not attachments:
            return AttachmentAnalysisResult()

        analyzed = []
        suspicious_count = 0
        total_risk = 0

        for att in attachments:
            finding = self._analyze_single(att)
            analyzed.append(finding)
            if finding.is_suspicious:
                suspicious_count += 1
            total_risk += finding.risk_points

        return AttachmentAnalysisResult(
            attachment_count=len(analyzed), attachments=analyzed,
            suspicious_count=suspicious_count, total_risk_points=min(total_risk, 60),
        )

    def _analyze_single(self, att: AttachmentFinding) -> AttachmentFinding:
        """Enrich an attachment finding with risk assessment."""
        findings_list = []
        risk_points = 0

        # Executable check
        if att.is_executable:
            findings_list.append("CRITICAL: Executable file detected")
            risk_points += 30

        # Script check
        if att.is_script:
            findings_list.append("HIGH: Script file detected")
            risk_points += 25

        # Macro-enabled document
        if att.is_macro_enabled:
            findings_list.append("HIGH: Macro-enabled Office document — may contain VBA malware")
            risk_points += 25

        # Double extension
        if att.has_double_extension:
            findings_list.append("HIGH: Double file extension — likely masquerading as safe file type")
            risk_points += 20

        # Archive files
        if att.is_archive:
            findings_list.append("MEDIUM: Archive file — may contain hidden malicious files")
            risk_points += 10

        # Suspicious MIME type mismatch
        if att.mime_type and att.extension:
            if self._is_mime_mismatch(att.mime_type, att.extension):
                findings_list.append(f"HIGH: MIME type '{att.mime_type}' doesn't match extension '{att.extension}'")
                risk_points += 20

        # Very large or very small files
        if att.file_size > 50 * 1024 * 1024:  # > 50MB
            findings_list.append("INFO: Unusually large attachment (>50MB)")
            risk_points += 5
        elif att.file_size < 100 and att.extension not in ('.txt', '.csv', '.url'):
            findings_list.append("MEDIUM: Unusually small file — may be a shortcut or dropper")
            risk_points += 10

        # Determine risk level
        if risk_points >= 25:
            risk_level = "critical"
        elif risk_points >= 15:
            risk_level = "high"
        elif risk_points >= 10:
            risk_level = "medium"
        elif risk_points > 0:
            risk_level = "low"
        else:
            risk_level = "safe"
            findings_list.append("No suspicious indicators detected")

        is_suspicious = risk_points >= 10

        return AttachmentFinding(
            filename=att.filename, file_size=att.file_size,
            file_size_human=att.file_size_human, mime_type=att.mime_type,
            extension=att.extension, md5=att.md5, sha1=att.sha1, sha256=att.sha256,
            is_executable=att.is_executable, is_script=att.is_script,
            is_archive=att.is_archive, is_macro_enabled=att.is_macro_enabled,
            has_double_extension=att.has_double_extension,
            is_suspicious=is_suspicious, risk_level=risk_level,
            risk_points=risk_points, findings=findings_list,
        )

    @staticmethod
    def _is_mime_mismatch(mime_type: str, extension: str) -> bool:
        """Check if MIME type doesn't match the file extension."""
        safe_mappings = {
            ".pdf": ["application/pdf"],
            ".doc": ["application/msword"],
            ".docx": ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
            ".xls": ["application/vnd.ms-excel"],
            ".xlsx": ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"],
            ".ppt": ["application/vnd.ms-powerpoint"],
            ".pptx": ["application/vnd.openxmlformats-officedocument.presentationml.presentation"],
            ".jpg": ["image/jpeg"],
            ".jpeg": ["image/jpeg"],
            ".png": ["image/png"],
            ".gif": ["image/gif"],
            ".txt": ["text/plain"],
            ".csv": ["text/csv", "text/plain"],
            ".zip": ["application/zip", "application/x-zip-compressed"],
            ".html": ["text/html"],
        }
        expected = safe_mappings.get(extension.lower(), [])
        if expected and mime_type not in expected:
            # Only flag if we have a known mapping and it doesn't match
            return True
        return False
