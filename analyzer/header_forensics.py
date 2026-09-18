"""
header_forensics.py
Analyzes email headers for spoofing signs: domain mismatches,
brand impersonation in display names, and suspicious hop chains.
"""

import re


def extract_domain(email_address):
    """
    Pulls just the domain out of an email address string.
    e.g. 'security@paypa1-verify.com' -> 'paypa1-verify.com'
    Handles the 'Display Name <email@domain.com>' format too.
    """
    if not email_address:
        return None
    # This regex finds anything that looks like an email inside <> or standalone
    match = re.search(r'[\w\.\-+]+@([\w\.\-]+)', email_address)
    if match:
        return match.group(1).lower()
    return None


def check_from_reply_mismatch(headers):
    """
    Compares the domain in 'From' vs 'Reply-To'.
    Legit emails: these usually match, or Reply-To is absent.
    Phishing: attacker wants replies going somewhere else, so domains differ.
    """
    from_header = headers.get("From", [None])[0]
    reply_to = headers.get("Reply-To", [None])[0]

    if not reply_to:
        return {"mismatch": False, "reason": "No Reply-To header present"}

    from_domain = extract_domain(from_header)
    reply_domain = extract_domain(reply_to)

    if from_domain and reply_domain and from_domain != reply_domain:
        return {
            "mismatch": True,
            "reason": f"From domain '{from_domain}' differs from Reply-To domain '{reply_domain}'"
        }
    return {"mismatch": False, "reason": "Domains match"}


def check_from_returnpath_mismatch(headers):
    """
    Compares 'From' domain vs 'Return-Path' domain.
    Return-Path is where bounce messages go - attackers often set this
    to a domain they actually control, different from the spoofed From.
    """
    from_header = headers.get("From", [None])[0]
    return_path = headers.get("Return-Path", [None])[0]

    if not return_path:
        return {"mismatch": False, "reason": "No Return-Path header present"}

    from_domain = extract_domain(from_header)
    return_domain = extract_domain(return_path)

    if from_domain and return_domain and from_domain != return_domain:
        return {
            "mismatch": True,
            "reason": f"From domain '{from_domain}' differs from Return-Path domain '{return_domain}'"
        }
    return {"mismatch": False, "reason": "Domains match"}


# Common brands attackers impersonate - not exhaustive, just a useful starter list
KNOWN_BRANDS = [
    "paypal", "amazon", "microsoft", "apple", "google",
    "netflix", "bank", "facebook", "instagram", "linkedin",
    "dhl", "fedex", "ups", "irs", "docusign",
]


def check_brand_impersonation(headers):
    """
    Looks at the display name in 'From' (e.g. 'PayPal Security Team')
    and checks if it mentions a known brand while the actual domain
    doesn't belong to that brand. This catches classic spoofing where
    the name looks legit but the domain doesn't.
    """
    from_header = headers.get("From", [None])[0]
    if not from_header:
        return {"impersonation": False, "reason": "No From header"}

    # Split display name from the actual email address
    match = re.match(r'^"?([^"<]*)"?\s*<?([\w\.\-+]+@[\w\.\-]+)?>?$', from_header.strip())
    if not match:
        return {"impersonation": False, "reason": "Could not parse From header"}

    display_name = match.group(1).strip().lower()
    domain = extract_domain(from_header)

    if not display_name or not domain:
        return {"impersonation": False, "reason": "Missing display name or domain"}

    for brand in KNOWN_BRANDS:
        if brand in display_name and brand not in domain:
            return {
                "impersonation": True,
                "reason": f"Display name mentions '{brand}' but domain is '{domain}' (not an official {brand} domain)"
            }

    return {"impersonation": False, "reason": "No brand impersonation detected"}


def get_hop_count(headers):
    """
    Counts how many mail servers this email passed through.
    Very few hops (1) can mean the email was sent directly from a
    script/spoofing tool rather than a normal mail provider chain.
    Very many hops can also be suspicious (relay hopping to hide origin).
    """
    received = headers.get("Received", [])
    return len(received)


def analyze_headers(headers):
    """
    Runs all header checks and returns one combined result dictionary.
    This is the function cli.py will actually call.
    """
    return {
        "from_reply_mismatch": check_from_reply_mismatch(headers),
        "from_returnpath_mismatch": check_from_returnpath_mismatch(headers),
        "brand_impersonation": check_brand_impersonation(headers),
        "hop_count": get_hop_count(headers),
    }
