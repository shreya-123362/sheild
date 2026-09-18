"""
parser.py
Reads a raw .eml file and extracts the structured parts we care about:
headers, plain text body, HTML body, and attachment list.
"""

from email import policy
from email.parser import BytesParser


def load_email(filepath):
    """
    Reads a .eml file from disk and returns a Python 'message' object.
    This object lets us access headers, body, and attachments cleanly.
    """
    with open(filepath, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg


def get_headers(msg):
    """
    Pulls out the headers we care about for phishing analysis.
    Returns a dictionary: {header_name: value}
    """
    important = [
        "From", "To", "Reply-To", "Return-Path",
        "Subject", "Date", "Message-ID",
        "Received", "Received-SPF",
        "Authentication-Results",
    ]
    headers = {}
    for h in important:
        values = msg.get_all(h)
        if values:
            headers[h] = values
    return headers


def get_body(msg):
    """
    Extracts plain text and HTML body separately.
    Emails often have both versions bundled together (multipart).
    """
    plain_text = None
    html = None

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain" and plain_text is None:
                plain_text = part.get_content()
            elif content_type == "text/html" and html is None:
                html = part.get_content()
    else:
        if msg.get_content_type() == "text/plain":
            plain_text = msg.get_content()
        elif msg.get_content_type() == "text/html":
            html = msg.get_content()

    return plain_text, html


def get_attachments(msg):
    """
    Returns a list of attachments as dicts: filename + raw bytes.
    """
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            attachments.append({
                "filename": part.get_filename(),
                "content_type": part.get_content_type(),
                "data": part.get_payload(decode=True),
            })
    return attachments
