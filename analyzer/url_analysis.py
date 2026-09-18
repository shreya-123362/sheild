"""
url_analysis.py
Extracts URLs from email body text/HTML, defangs them for safe reporting,
and flags basic suspicious patterns.
"""

import re


def extract_urls(text):
    """
    Finds all http(s) URLs inside a block of text using regex.
    """
    if not text:
        return []

    url_pattern = r'https?://[^\s"\'<>]+'
    urls = re.findall(url_pattern, text)

    return list(dict.fromkeys(urls))


def defang_url(url):
    """
    Rewrites a URL so it's safe to paste into chat/reports without
    it becoming a clickable link.
    """
    defanged = url.replace("http://", "hxxp://")
    defanged = defanged.replace("https://", "hxxps://")
    defanged = defanged.replace(".", "[.]")
    return defanged


def get_domain_from_url(url):
    """
    Extracts just the domain from a full URL.
    """
    match = re.match(r'https?://([^/]+)', url)
    if match:
        return match.group(1).lower()
    return None


def is_ip_address(domain):
    """
    Checks if a 'domain' is actually a raw IP address.
    """
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    return bool(re.match(ip_pattern, domain)) if domain else False


def count_subdomains(domain):
    """
    Counts how many subdomain levels a domain has.
    """
    if not domain:
        return 0
    return domain.count(".")


def check_lookalike_domain(domain):
    """
    Catches domains trying to LOOK like a known brand but aren't -
    e.g. 'paypa1-verify.com' instead of 'paypal.com'.
    """
    if not domain:
        return None

    from analyzer.header_forensics import KNOWN_BRANDS

    # Only digit -> letter direction, since that's the direction
    # typosquatting actually goes (never the reverse).
    substitutions = {
        "1": "l",
        "0": "o",
        "3": "e",
        "4": "a",
        "5": "s",
        "rn": "m",
    }

    domain_normalized = domain
    for fake, real in substitutions.items():
        domain_normalized = domain_normalized.replace(fake, real)

    for brand in KNOWN_BRANDS:
        if brand in domain_normalized and brand not in domain:
            return f"Domain '{domain}' looks like a lookalike of '{brand}' (character substitution trick)"

    return None


def analyze_urls(plain_text, html):
    """
    Runs the full URL analysis pipeline: extract from both plain text
    and HTML, dedupe, then flag suspicious ones.
    """
    urls = set()
    urls.update(extract_urls(plain_text))
    urls.update(extract_urls(html))

    results = []
    for url in urls:
        domain = get_domain_from_url(url)
        flags = []

        if is_ip_address(domain):
            flags.append("URL uses a raw IP address instead of a domain name")

        if domain and count_subdomains(domain) >= 4:
            flags.append(f"Unusually high number of subdomains ({count_subdomains(domain)} dots)")

        lookalike = check_lookalike_domain(domain)
        if lookalike:
            flags.append(lookalike)

        results.append({
            "original": url,
            "defanged": defang_url(url),
            "domain": domain,
            "flags": flags,
        })

    return results
