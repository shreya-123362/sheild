"""
auth_checks.py
Parses SPF, DKIM, and DMARC results out of the Authentication-Results
header into clean, structured pass/fail values.
"""

import re


def parse_authentication_results(headers):
    """
    Authentication-Results looks like one long messy string, e.g.:
    'mx.google.com; spf=fail ...; dkim=fail ...; dmarc=fail (p=REJECT ...)'

    We pull out just the spf=, dkim=, dmarc= values using regex,
    since their format is fairly consistent across mail providers.
    """
    auth_header = headers.get("Authentication-Results", [None])[0]

    result = {
        "spf": "not found",
        "dkim": "not found",
        "dmarc": "not found",
        "dmarc_policy": None,
    }

    if not auth_header:
        return result

    # Each of these looks for "spf=" followed by a word (pass/fail/none/etc.)
    spf_match = re.search(r'spf=(\w+)', auth_header)
    dkim_match = re.search(r'dkim=(\w+)', auth_header)
    dmarc_match = re.search(r'dmarc=(\w+)', auth_header)
    # DMARC policy is nested differently: p=REJECT / p=QUARANTINE / p=NONE
    policy_match = re.search(r'p=(\w+)', auth_header)

    if spf_match:
        result["spf"] = spf_match.group(1).lower()
    if dkim_match:
        result["dkim"] = dkim_match.group(1).lower()
    if dmarc_match:
        result["dmarc"] = dmarc_match.group(1).lower()
    if policy_match:
        result["dmarc_policy"] = policy_match.group(1).lower()

    return result


def check_received_spf(headers):
    """
    Some mail providers also add a separate 'Received-SPF' header,
    which is simpler to read than digging through Authentication-Results.
    We check this as a backup/cross-reference.
    """
    received_spf = headers.get("Received-SPF", [None])[0]
    if not received_spf:
        return "not found"

    # This header usually starts with the word: pass, fail, softfail, neutral, none
    match = re.match(r'^(\w+)', received_spf.strip())
    if match:
        return match.group(1).lower()
    return "unknown"


def analyze_auth(headers):
    """
    Combines all auth checks into one result, plus a simple
    'all_pass' boolean that later feeds into the risk scorer.
    """
    auth_results = parse_authentication_results(headers)
    received_spf = check_received_spf(headers)

    # "pass" is a pass; anything else (fail, softfail, none, not found) counts against it
    spf_ok = auth_results["spf"] == "pass" or received_spf == "pass"
    dkim_ok = auth_results["dkim"] == "pass"
    dmarc_ok = auth_results["dmarc"] == "pass"

    return {
        "spf": auth_results["spf"],
        "received_spf_header": received_spf,
        "dkim": auth_results["dkim"],
        "dmarc": auth_results["dmarc"],
        "dmarc_policy": auth_results["dmarc_policy"],
        "all_pass": spf_ok and dkim_ok and dmarc_ok,
    }
