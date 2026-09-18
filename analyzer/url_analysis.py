"""
url_analysis.py
Extracts URLs from email body text/HTML, defangs them for safe reporting,
and flags basic suspicious patterns.
"""

import re


def extract_urls(text):
    """
    Finds all http(s) URLs inside a block of text using regex.
    Works on both plain text and raw HTML (it just looks for the
    http:// or https:// pattern, doesn't care what surrounds it).
    """
    if not text:
        return []

    # Matches http:// or https:// followed by non-whitespace, non-quote chars
    url_pattern = r'https?://[^\s"\'<>]+'
    urls = re.findall(url_pattern, text)

    # Dedupe while preserving order (dict.fromkeys is a common Python trick for this)
    return list(dict.fromkeys(urls))


def defang_url(url):
    """
    Rewrites a URL so it's safe to paste into chat/reports without
    it becoming a clickable link. Standard SOC analyst practice.
    e.g. http://evil.com -> hxxp://evil[.]com
    """
    defanged = url.replace("http://", "hxxp://")
    defanged = defanged.replace("https://", "hxxps://")
    defanged = defanged.replace(".", "[.]")
    return defanged


def get_domain_from_url(url):
    """
    Extracts just the domain from a full URL.
    e.g. http://paypa1-verify.com/login?id=123 -> paypa1-verify.com
    """
    match = re.match(r'https?://([^/]+)', url)
    if match:
        return match.group(1).lower()
    return None


def is_ip_address(domain):
    """
    Checks if a 'domain' is actually a raw IP address (e.g. http://192.168.1.1/login).
    Legit companies basically never link directly to a bare IP - this is
    almost always a red flag or a compromised/throwaway server.
    """
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    return bool(re.match(ip_pattern, domain)) if domain else False


def count_subdomains(domain):
    """
    Counts how many subdomain levels a domain has.
    e.g. 'secure.login.paypal.verify-account.com' has a LOT of dots -
    attackers pile on subdomains to make fake URLs look more official.
    """
    if not domain:
        return 0
    return domain.count(".")


def analyze_urls(plain_text, html):
    """
    Runs the full URL analysis pipeline: extract from both plain text
    and HTML, dedupe, then flag suspicious ones.
    Returns a list of dicts, one per unique URL found.
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

        results.append({
            "original": url,
            "defanged": defang_url(url),
            "domain": domain,
            "flags": flags,
        })

    return results
