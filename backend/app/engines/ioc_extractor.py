"""
IOC Extractor Engine
Extracts Indicators of Compromise (IPs, domains, URLs, hashes, emails)
from email content using regex patterns.
"""
import logging
import re
from typing import Optional

from app.schemas import IOCItem, IOCSummary
from app.utils.sanitizer import defang_url, defang_ip, defang_email, defang_domain

logger = logging.getLogger(__name__)

# Regex patterns for IOC extraction
IPV4_REGEX = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

IPV6_REGEX = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
    r'\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b'
)

DOMAIN_REGEX = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
)

URL_REGEX = re.compile(
    r'https?://[^\s<>"\')\]]+',
    re.IGNORECASE,
)

EMAIL_REGEX = re.compile(
    r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
)

MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_REGEX = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')

# Internal/private IPs and common domains to exclude
PRIVATE_IP_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "127.", "0.", "169.254.")

EXCLUDE_DOMAINS = {
    "w3.org", "schema.org", "schemas.microsoft.com", "schemas.openxmlformats.org",
    "xmlns.com", "purl.org", "example.com", "example.org", "localhost",
    "fonts.googleapis.com", "fonts.gstatic.com",
}


class IOCExtractor:
    """Extracts and deduplicates IOCs from email content."""

    def extract(self, body_text: Optional[str] = None, body_html: Optional[str] = None,
                raw_headers: Optional[str] = None, attachment_hashes: Optional[list[dict]] = None) -> IOCSummary:
        logger.info("Extracting IOCs", extra={"engine": "ioc_extractor"})

        combined = ""
        if raw_headers:
            combined += raw_headers + " "
        if body_text:
            combined += body_text + " "
        if body_html:
            combined += body_html

        ips = self._extract_ips(combined)
        domains = self._extract_domains(combined)
        urls = self._extract_urls(combined)
        emails = self._extract_emails(combined)
        hashes = self._extract_hashes(combined, attachment_hashes)

        total = len(ips) + len(domains) + len(urls) + len(emails) + len(hashes)

        return IOCSummary(
            total_count=total, ips=ips, domains=domains,
            urls=urls, hashes=hashes, emails=emails,
        )

    def _extract_ips(self, text: str) -> list[IOCItem]:
        results = []
        seen = set()
        for match in IPV4_REGEX.finditer(text):
            ip = match.group(0)
            if ip in seen or any(ip.startswith(p) for p in PRIVATE_IP_PREFIXES):
                continue
            seen.add(ip)
            results.append(IOCItem(
                ioc_type="ip", value=ip, defanged=defang_ip(ip), context="Extracted from email",
            ))
        for match in IPV6_REGEX.finditer(text):
            ip = match.group(0)
            if ip not in seen:
                seen.add(ip)
                results.append(IOCItem(
                    ioc_type="ip", value=ip, defanged=ip, context="IPv6 address",
                ))
        return results[:100]

    def _extract_domains(self, text: str) -> list[IOCItem]:
        results = []
        seen = set()
        for match in DOMAIN_REGEX.finditer(text):
            domain = match.group(0).lower()
            if domain in seen or domain in EXCLUDE_DOMAINS:
                continue
            # Skip if it looks like an IP
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
                continue
            seen.add(domain)
            results.append(IOCItem(
                ioc_type="domain", value=domain, defanged=defang_domain(domain),
                context="Extracted from email",
            ))
        return results[:100]

    def _extract_urls(self, text: str) -> list[IOCItem]:
        results = []
        seen = set()
        for match in URL_REGEX.finditer(text):
            url = match.group(0).rstrip(".,;:!?)")
            if url in seen:
                continue
            seen.add(url)
            results.append(IOCItem(
                ioc_type="url", value=url, defanged=defang_url(url),
                context="Extracted from email",
            ))
        return results[:100]

    def _extract_emails(self, text: str) -> list[IOCItem]:
        results = []
        seen = set()
        for match in EMAIL_REGEX.finditer(text):
            addr = match.group(0).lower()
            if addr in seen:
                continue
            seen.add(addr)
            results.append(IOCItem(
                ioc_type="email", value=addr, defanged=defang_email(addr),
                context="Extracted from email",
            ))
        return results[:50]

    def _extract_hashes(self, text: str, attachment_hashes: Optional[list[dict]] = None) -> list[IOCItem]:
        results = []
        seen = set()

        # From attachment analysis
        if attachment_hashes:
            for h in attachment_hashes:
                for hash_type in ["md5", "sha1", "sha256"]:
                    val = h.get(hash_type)
                    if val and val not in seen:
                        seen.add(val)
                        results.append(IOCItem(
                            ioc_type=f"hash_{hash_type}", value=val, defanged=val,
                            context=f"Attachment: {h.get('filename', 'unknown')}",
                        ))

        # From text (less reliable — may match non-hash hex strings)
        for regex, hash_type in [(SHA256_REGEX, "hash_sha256"), (SHA1_REGEX, "hash_sha1"), (MD5_REGEX, "hash_md5")]:
            for match in regex.finditer(text):
                val = match.group(0).lower()
                if val not in seen:
                    seen.add(val)
                    results.append(IOCItem(
                        ioc_type=hash_type, value=val, defanged=val,
                        context="Extracted from email text",
                    ))

        return results[:50]
