"""
HTML sanitization utilities to prevent XSS when rendering email content.
"""
import bleach
import re


# Allowed tags for safe HTML email rendering
ALLOWED_TAGS = [
    "a", "abbr", "b", "blockquote", "br", "code", "div", "em",
    "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "li", "ol",
    "p", "pre", "span", "strong", "table", "tbody", "td", "th",
    "thead", "tr", "u", "ul", "img",
]

ALLOWED_ATTRIBUTES = {
    "a": ["href", "title", "target"],
    "img": ["src", "alt", "width", "height"],
    "td": ["colspan", "rowspan"],
    "th": ["colspan", "rowspan"],
    "div": ["class"],
    "span": ["class"],
    "table": ["class", "border", "cellpadding", "cellspacing"],
}

ALLOWED_PROTOCOLS = ["http", "https", "mailto"]


def sanitize_html(html_content: str) -> str:
    """
    Sanitize HTML email content to prevent XSS.
    Strips dangerous tags, attributes, and protocols.
    """
    if not html_content:
        return ""

    cleaned = bleach.clean(
        html_content,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=True,
    )
    return cleaned


def strip_html_to_text(html_content: str) -> str:
    """Strip all HTML tags, returning plain text."""
    if not html_content:
        return ""
    text = bleach.clean(html_content, tags=[], strip=True)
    # Collapse whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def defang_url(url: str) -> str:
    """Defang a URL for safe display (hxxps://example[.]com)."""
    url = url.replace("http://", "hxxp://")
    url = url.replace("https://", "hxxps://")
    url = url.replace("://", "[://]")
    url = re.sub(r'\.(?=[a-zA-Z]{2,})', '[.]', url, count=1)
    return url


def defang_ip(ip: str) -> str:
    """Defang an IP address (1.2.3[.]4)."""
    parts = ip.rsplit(".", 1)
    if len(parts) == 2:
        return f"{parts[0]}[.]{parts[1]}"
    return ip


def defang_email(email: str) -> str:
    """Defang an email address (user[@]domain[.]com)."""
    email = email.replace("@", "[@]")
    # Defang domain part
    at_pos = email.find("[@]")
    if at_pos > -1:
        domain = email[at_pos + 3:]
        domain = re.sub(r'\.(?=[a-zA-Z]{2,})', '[.]', domain, count=1)
        email = email[:at_pos + 3] + domain
    return email


def defang_domain(domain: str) -> str:
    """Defang a domain (example[.]com)."""
    return re.sub(r'\.(?=[a-zA-Z]{2,})', '[.]', domain, count=1)
