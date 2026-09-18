"""
attachment_analysis.py
Computes cryptographic hashes for email attachments so they can be
checked against threat intelligence databases (VirusTotal, etc.)
without ever needing to open/execute the file.
"""

import hashlib


# Extensions that are commonly weaponized in phishing attachments
DANGEROUS_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".jar", ".msi", ".dll", ".iso", ".lnk",
    ".docm", ".xlsm", ".pptm",  # macro-enabled Office files
]


def compute_hashes(data):
    """
    Computes MD5, SHA1, and SHA256 hashes of raw file bytes.
    A hash is a fixed-length fingerprint - the same file always
    produces the same hash, and changing even one byte changes it
    completely. This lets us identify a file without opening it,
    and check if that exact fingerprint is already known-malicious.
    """
    if not data:
        return None

    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def check_dangerous_extension(filename):
    """
    Flags if the attachment's file extension is commonly used
    to deliver malware.
    """
    if not filename:
        return False
    filename_lower = filename.lower()
    return any(filename_lower.endswith(ext) for ext in DANGEROUS_EXTENSIONS)


def analyze_attachments(attachments):
    """
    Runs hash computation + extension check on every attachment.
    Returns a list of dicts, one per attachment.
    """
    results = []
    for att in attachments:
        hashes = compute_hashes(att["data"])
        dangerous = check_dangerous_extension(att["filename"])

        results.append({
            "filename": att["filename"],
            "content_type": att["content_type"],
            "size_bytes": len(att["data"]) if att["data"] else 0,
            "hashes": hashes,
            "dangerous_extension": dangerous,
        })

    return results
