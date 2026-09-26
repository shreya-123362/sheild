"""
header_forensics.py
Analyzes email headers for spoofing signs: domain mismatches,
brand impersonation in display names, and suspicious hop chains.
"""

import re


def extract_domain(email_address):
    """
    Pulls just the domain out of an email address string.
    """
    if not email_address:
        return None
    match = re.search(r'[\w\.\-+]+@([\w\.\-]+)', email_address)
    if match:
        return match.group(1).lower()
    return None


def is_subdomain_of(possible_subdomain, base_domain):
    """
    Checks if 'possible_subdomain' is actually a subdomain of 'base_domain'.
    e.g. is_subdomain_of('fdesp.hackingflix.com', 'hackingflix.com') -> True
    This matters because legit marketing platforms (Flodesk, Mailchimp, etc.)
    commonly use a bounce-handling subdomain that's DIFFERENT from the main
    domain but still clearly belongs to the same organization - not a
    real spoofing signal.
    """
    if not possible_subdomain or not base_domain:
        return False
    return possible_subdomain == base_domain or possible_subdomain.endswith("." + base_domain)


def check_from_reply_mismatch(headers):
    """
    Compares the domain in 'From' vs 'Reply-To'.
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
    A subdomain relationship (e.g. bounce.company.com for from@company.com)
    is treated as legitimate, since this is standard practice for
    email marketing platforms and transactional mail services.
    Only a COMPLETELY unrelated domain is flagged as suspicious.
    """
    from_header = headers.get("From", [None])[0]
    return_path = headers.get("Return-Path", [None])[0]

    if not return_path:
        return {"mismatch": False, "reason": "No Return-Path header present"}

    from_domain = extract_domain(from_header)
    return_domain = extract_domain(return_path)

    if not from_domain or not return_domain:
        return {"mismatch": False, "reason": "Could not determine domains"}

    if from_domain == return_domain:
        return {"mismatch": False, "reason": "Domains match"}

    if is_subdomain_of(return_domain, from_domain) or is_subdomain_of(from_domain, return_domain):
        return {
            "mismatch": False,
            "reason": f"Return-Path domain '{return_domain}' is a related subdomain of From domain '{from_domain}' (common for marketing/transactional mail)"
        }

    return {
        "mismatch": True,
        "reason": f"From domain '{from_domain}' differs from Return-Path domain '{return_domain}'"
    }


KNOWN_BRANDS = [
    "paypal", "amazon", "microsoft", "apple", "google",
    "netflix", "bank", "facebook", "instagram", "linkedin",
    "dhl", "fedex", "ups", "irs", "docusign",
]


def check_brand_impersonation(headers):
    """
    Looks at the display name in 'From' and checks if it mentions a
    known brand while the actual domain doesn't belong to that brand.
    """
    from_header = headers.get("From", [None])[0]
    if not from_header:
        return {"impersonation": False, "reason": "No From header"}

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
    """
    received = headers.get("Received", [])
    return len(received)


def analyze_headers(headers):
    """
    Runs all header checks and returns one combined result dictionary.
    """
    return {
        "from_reply_mismatch": check_from_reply_mismatch(headers),
        "from_returnpath_mismatch": check_from_returnpath_mismatch(headers),
        "brand_impersonation": check_brand_impersonation(headers),
        "hop_count": get_hop_count(headers),
    }
