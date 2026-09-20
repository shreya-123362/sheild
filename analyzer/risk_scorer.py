"""
risk_scorer.py
Combines findings from all analysis modules (headers, auth, URLs,
attachments) into one overall risk score and verdict.
"""


def score_email(header_results, auth_results, url_results, attachment_results, content_results):
    """
    Takes the output of all four analyzer modules and produces:
    - a numeric score (0-100)
    - a risk level (Low / Medium / High / Critical)
    - a list of human-readable reasons explaining the score

    Point values are deliberately weighted: authentication failures and
    brand impersonation are the strongest signals, URL/attachment flags
    add smaller increments since they're more heuristic/fuzzy.
    """
    score = 0
    reasons = []

    # --- Header forensics ---
    if header_results["from_reply_mismatch"]["mismatch"]:
        score += 20
        reasons.append(header_results["from_reply_mismatch"]["reason"])

    if header_results["from_returnpath_mismatch"]["mismatch"]:
        score += 15
        reasons.append(header_results["from_returnpath_mismatch"]["reason"])

    if header_results["brand_impersonation"]["impersonation"]:
        score += 25
        reasons.append(header_results["brand_impersonation"]["reason"])

    # --- Authentication (SPF/DKIM/DMARC) ---
    if not auth_results["all_pass"]:
        failed = []
        if auth_results["spf"] != "pass":
            failed.append("SPF")
        if auth_results["dkim"] != "pass":
            failed.append("DKIM")
        if auth_results["dmarc"] != "pass":
            failed.append("DMARC")
        score += 10 * len(failed)
        reasons.append(f"Authentication failed: {', '.join(failed)}")

    # --- URLs ---
    for url in url_results:
        for flag in url["flags"]:
            score += 10
            reasons.append(flag)

    # --- Attachments ---
    for att in attachment_results:
        if att["dangerous_extension"]:
            score += 20
            reasons.append(f"Attachment '{att['filename']}' has a dangerous file extension")

   
    # --- Content analysis ---
    if content_results["urgency_phrases"]:
        score += 5
        reasons.append(f"Urgency language found: {', '.join(content_results['urgency_phrases'])}")

    if content_results["threat_phrases"]:
        score += 10
        reasons.append(f"Threat language found: {', '.join(content_results['threat_phrases'])}")

    if content_results["generic_greeting"]:
        score += 5
        reasons.append(f"Generic greeting found: {', '.join(content_results['generic_greeting'])}")

    # Cap at 100 - lots of small flags shouldn't produce a nonsensical score like 250
    score = min(score, 100)

    # Convert score into a human verdict
    if score >= 70:
        level = "Critical"
    elif score >= 45:
        level = "High"
    elif score >= 20:
        level = "Medium"
    else:
        level = "Low"

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
    }
