"""
Email Parser Engine
Handles parsing of .eml files, .msg files, and raw email headers/body.
Extracts all metadata, headers, body content, and attachments.
"""
import email
import email.policy
import hashlib
import logging
import os
import re
from email import utils as email_utils
from email.message import EmailMessage
from typing import Optional

from app.schemas import EmailMetadata, AttachmentFinding
from app.utils.sanitizer import sanitize_html
from app.utils.validators import humanize_bytes

logger = logging.getLogger(__name__)


class EmailParser:
    """
    Parses email files (.eml, .msg) and raw header text into structured data.
    All file processing is in-memory — no temp files written to disk.
    """

    def parse_eml(self, file_content: bytes) -> tuple[EmailMetadata, list[AttachmentFinding], dict]:
        """
        Parse a .eml file from raw bytes.
        Returns (metadata, attachments, raw_headers_dict).
        """
        logger.info("Parsing .eml file", extra={"engine": "email_parser"})
        msg = email.message_from_bytes(file_content, policy=email.policy.default)
        return self._extract_from_message(msg)

    def parse_msg(self, file_content: bytes) -> tuple[EmailMetadata, list[AttachmentFinding], dict]:
        """
        Parse a .msg (Outlook) file from raw bytes.
        Returns (metadata, attachments, raw_headers_dict).
        """
        logger.info("Parsing .msg file", extra={"engine": "email_parser"})
        try:
            import extract_msg
            import io

            msg = extract_msg.Message(io.BytesIO(file_content))

            # Build metadata from msg object
            metadata = EmailMetadata(
                sender=msg.sender or "",
                sender_name=self._extract_name(msg.sender or ""),
                sender_email=self._extract_email_addr(msg.sender or ""),
                recipient=msg.to or "",
                cc=self._split_addresses(msg.cc) if msg.cc else [],
                bcc=self._split_addresses(msg.bcc) if msg.bcc else [],
                subject=msg.subject or "",
                date=str(msg.date) if msg.date else None,
                message_id=msg.messageId if hasattr(msg, 'messageId') else None,
                body_text=msg.body or "",
                body_html=sanitize_html(msg.htmlBody.decode("utf-8", errors="replace")) if msg.htmlBody else None,
                has_attachments=len(msg.attachments) > 0,
                attachment_count=len(msg.attachments),
            )

            # Extract attachments
            attachments = []
            for att in msg.attachments:
                att_data = att.data if hasattr(att, 'data') else b""
                if isinstance(att_data, str):
                    att_data = att_data.encode("utf-8")
                if att_data:
                    attachments.append(self._build_attachment_finding(
                        filename=att.longFilename or att.shortFilename or "unknown",
                        data=att_data,
                    ))

            # Build headers dict from msg headers if available
            raw_headers = {}
            if hasattr(msg, 'headerDict') and msg.headerDict:
                raw_headers = dict(msg.headerDict)
            elif hasattr(msg, 'header') and msg.header:
                raw_headers = self._parse_raw_header_text(msg.header.as_string() if hasattr(msg.header, 'as_string') else str(msg.header))

            msg.close()
            return metadata, attachments, raw_headers

        except ImportError:
            logger.error("extract-msg not installed, cannot parse .msg files")
            raise ValueError("MSG file parsing requires the 'extract-msg' package")
        except Exception as e:
            logger.error(f"Failed to parse .msg file: {e}", exc_info=True)
            raise ValueError(f"Failed to parse MSG file: {str(e)}")

    def parse_raw_headers(
        self,
        raw_headers: str,
        body_text: Optional[str] = None,
        body_html: Optional[str] = None,
    ) -> tuple[EmailMetadata, list[AttachmentFinding], dict]:
        """
        Parse raw email headers (and optional body) from text input.
        Returns (metadata, [], raw_headers_dict).
        """
        logger.info("Parsing raw headers", extra={"engine": "email_parser"})

        # Try to parse as a full email first
        try:
            full_content = raw_headers
            if body_text:
                full_content += f"\n\n{body_text}"
            msg = email.message_from_string(full_content, policy=email.policy.default)
            metadata, attachments, headers = self._extract_from_message(msg)
        except Exception:
            # Fall back to manual header parsing
            headers = self._parse_raw_header_text(raw_headers)
            metadata = EmailMetadata(
                sender=headers.get("From", ""),
                sender_name=self._extract_name(headers.get("From", "")),
                sender_email=self._extract_email_addr(headers.get("From", "")),
                reply_to=headers.get("Reply-To"),
                return_path=headers.get("Return-Path"),
                recipient=headers.get("To", ""),
                cc=self._split_addresses(headers.get("Cc", "")),
                bcc=self._split_addresses(headers.get("Bcc", "")),
                subject=headers.get("Subject", ""),
                date=headers.get("Date"),
                message_id=headers.get("Message-ID"),
                mime_version=headers.get("MIME-Version"),
                content_type=headers.get("Content-Type"),
                x_mailer=headers.get("X-Mailer"),
                all_headers=headers,
                body_text=body_text or "",
                body_html=sanitize_html(body_html) if body_html else None,
            )
            attachments = []

        # Override body if provided separately
        if body_text and not metadata.body_text:
            metadata.body_text = body_text
        if body_html:
            metadata.body_html = sanitize_html(body_html)

        return metadata, attachments, headers

    # ================================================================
    # Internal helpers
    # ================================================================

    def _extract_from_message(
        self, msg: EmailMessage
    ) -> tuple[EmailMetadata, list[AttachmentFinding], dict]:
        """Extract structured data from a parsed email.Message object."""

        # Collect all headers
        raw_headers = {}
        received_headers = []
        for key, value in msg.items():
            if key.lower() == "received":
                received_headers.append(value)
            raw_headers[key] = value

        # Extract body parts
        body_text = ""
        body_html = ""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                if "attachment" in content_disposition or content_type not in (
                    "text/plain", "text/html", "multipart/mixed", "multipart/alternative",
                    "multipart/related",
                ):
                    # It's an attachment
                    payload = part.get_payload(decode=True)
                    if payload:
                        filename = part.get_filename() or f"unnamed.{content_type.split('/')[-1]}"
                        attachments.append(self._build_attachment_finding(filename, payload))
                elif content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_text += payload.decode("utf-8", errors="replace")
                elif content_type == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_html += payload.decode("utf-8", errors="replace")
        else:
            content_type = msg.get_content_type()
            payload = msg.get_payload(decode=True)
            if payload:
                if content_type == "text/html":
                    body_html = payload.decode("utf-8", errors="replace")
                else:
                    body_text = payload.decode("utf-8", errors="replace")

        from_header = msg.get("From", "")
        metadata = EmailMetadata(
            sender=from_header,
            sender_name=self._extract_name(from_header),
            sender_email=self._extract_email_addr(from_header),
            reply_to=msg.get("Reply-To"),
            return_path=msg.get("Return-Path"),
            recipient=msg.get("To", ""),
            cc=self._split_addresses(msg.get("Cc", "") or ""),
            bcc=self._split_addresses(msg.get("Bcc", "") or ""),
            subject=msg.get("Subject", ""),
            date=msg.get("Date"),
            message_id=msg.get("Message-ID"),
            mime_version=msg.get("MIME-Version"),
            content_type=msg.get("Content-Type"),
            x_mailer=msg.get("X-Mailer"),
            received_headers=received_headers,
            all_headers=raw_headers,
            body_text=body_text,
            body_html=sanitize_html(body_html) if body_html else None,
            has_attachments=len(attachments) > 0,
            attachment_count=len(attachments),
        )

        return metadata, attachments, raw_headers

    def _build_attachment_finding(self, filename: str, data: bytes) -> AttachmentFinding:
        """Build an AttachmentFinding from raw attachment data."""
        from app.utils.validators import classify_file_extension

        classification = classify_file_extension(filename)

        # Detect MIME type
        mime_type = None
        try:
            import magic
            mime_type = magic.from_buffer(data, mime=True)
        except Exception:
            pass

        return AttachmentFinding(
            filename=filename,
            file_size=len(data),
            file_size_human=humanize_bytes(len(data)),
            mime_type=mime_type,
            extension=classification["extension"],
            md5=hashlib.md5(data).hexdigest(),
            sha1=hashlib.sha1(data).hexdigest(),
            sha256=hashlib.sha256(data).hexdigest(),
            is_executable=classification["is_executable"],
            is_script=classification["is_script"],
            is_archive=classification["is_archive"],
            is_macro_enabled=classification["is_macro_enabled"],
            has_double_extension=classification["has_double_extension"],
        )

    def _parse_raw_header_text(self, raw_text: str) -> dict[str, str]:
        """Parse raw header text into a dict, handling line continuations."""
        headers = {}
        current_key = None
        current_value = ""

        for line in raw_text.split("\n"):
            if not line.strip():
                continue
            # Line continuation (starts with whitespace)
            if line[0] in (" ", "\t") and current_key:
                current_value += " " + line.strip()
            else:
                # Save previous header
                if current_key:
                    headers[current_key] = current_value
                # Parse new header
                if ":" in line:
                    current_key, _, current_value = line.partition(":")
                    current_key = current_key.strip()
                    current_value = current_value.strip()
                else:
                    current_key = None
                    current_value = ""

        # Save last header
        if current_key:
            headers[current_key] = current_value

        return headers

    @staticmethod
    def _extract_email_addr(from_header: str) -> str:
        """Extract email address from a From header like 'Name <email@domain.com>'."""
        match = re.search(r'<([^>]+)>', from_header)
        if match:
            return match.group(1).strip()
        # Maybe it's just an email address
        match = re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', from_header)
        if match:
            return match.group(0)
        return from_header.strip()

    @staticmethod
    def _extract_name(from_header: str) -> str:
        """Extract display name from a From header."""
        match = re.match(r'^"?([^"<]+)"?\s*<', from_header)
        if match:
            return match.group(1).strip()
        return ""

    @staticmethod
    def _split_addresses(addr_string: str) -> list[str]:
        """Split a comma-separated address list."""
        if not addr_string:
            return []
        return [a.strip() for a in addr_string.split(",") if a.strip()]
