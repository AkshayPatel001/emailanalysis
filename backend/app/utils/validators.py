"""
Input validation utilities for file uploads and data.
"""
import os
from fastapi import UploadFile, HTTPException

# Maximum allowed file extensions for email uploads
ALLOWED_EMAIL_EXTENSIONS = {".eml", ".msg", ".txt"}

# Dangerous file types that should never be executed
DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".hta", ".cpl", ".msi", ".msp",
    ".com", ".pif", ".reg", ".inf", ".lnk", ".application",
}

# Macro-enabled Office extensions
MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm",
    ".xlam", ".ppam", ".sldm",
}

# Archive extensions
ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".cab", ".iso", ".dmg",
}

# Script extensions
SCRIPT_EXTENSIONS = {
    ".py", ".rb", ".pl", ".sh", ".bash", ".php", ".asp", ".aspx",
    ".jsp", ".cgi",
}


def validate_email_upload(file: UploadFile, max_size_bytes: int) -> None:
    """
    Validate an uploaded email file.
    Raises HTTPException if invalid.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EMAIL_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Allowed: {', '.join(ALLOWED_EMAIL_EXTENSIONS)}",
        )

    # Check content length if available
    if file.size and file.size > max_size_bytes:
        max_mb = max_size_bytes / (1024 * 1024)
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size: {max_mb:.0f} MB",
        )


def classify_file_extension(filename: str) -> dict:
    """
    Classify a file by its extension.
    Returns dict with boolean flags.
    """
    ext = os.path.splitext(filename)[1].lower()
    return {
        "extension": ext,
        "is_executable": ext in DANGEROUS_EXTENSIONS,
        "is_macro_enabled": ext in MACRO_EXTENSIONS,
        "is_archive": ext in ARCHIVE_EXTENSIONS,
        "is_script": ext in SCRIPT_EXTENSIONS,
        "is_dangerous": ext in DANGEROUS_EXTENSIONS or ext in MACRO_EXTENSIONS,
        "has_double_extension": filename.count(".") > 1 and ext in DANGEROUS_EXTENSIONS,
    }


def humanize_bytes(size_bytes: int) -> str:
    """Convert bytes to human-readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(size_bytes) < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"
