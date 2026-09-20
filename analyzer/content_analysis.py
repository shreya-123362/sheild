"""
content_analysis.py
Scans the email body text for social engineering patterns:
urgency language, threats, and generic (non-personalized) greetings.
"""

import re


# Phrases commonly used to pressure the reader into acting fast
URGENCY_PHRASES = [
    "act now", "act immediately", "urgent", "immediately",
    "within 24 hours", "within 48 hours", "right away",
    "as soon as possible", "time sensitive", "expires soon",
    "final notice", "last chance",
]

# Phrases implying a negative consequence if the reader doesn't comply
THREAT_PHRASES = [
    "account suspended", "account limited", "account locked",
    "permanently suspended", "will be closed", "will be terminated",
    "legal action", "unauthorized access", "unusual activity",
    "suspicious activity", "verify your identity",
]

# Generic greetings phishing emails use since they don't know your real name
GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear valued customer",
    "dear account holder", "dear member", "dear sir/madam",
    "dear client",
]


def check_phrases(text, phrase_list):
    """
    Checks how many phrases from a given list appear in the text.
    Case-insensitive, since phishing text capitalization is inconsistent.
    Returns the list of phrases that actually matched.
    """
    if not text:
        return []

    text_lower = text.lower()
    found = [phrase for phrase in phrase_list if phrase in text_lower]
    return found


def analyze_content(plain_text, html):
    """
    Runs all body-text checks. Combines plain_text and html into one
    blob to search, since some emails only put text in one or the other.
    """
    combined_text = (plain_text or "") + " " + (html or "")

    urgency_found = check_phrases(combined_text, URGENCY_PHRASES)
    threats_found = check_phrases(combined_text, THREAT_PHRASES)
    generic_greeting_found = check_phrases(combined_text, GENERIC_GREETINGS)

    return {
        "urgency_phrases": urgency_found,
        "threat_phrases": threats_found,
        "generic_greeting": generic_greeting_found,
    }
