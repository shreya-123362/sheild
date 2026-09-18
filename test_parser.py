"""
test_parser.py
Quick sanity check: loads example.eml and prints what the parser extracted.
Not the final tool - just proving Step 2 works before we build on top of it.
"""

from analyzer.parser import load_email, get_headers, get_body, get_attachments

# Load the email
msg = load_email("samples/example.eml")

# Print headers
print("=" * 50)
print("HEADERS")
print("=" * 50)
headers = get_headers(msg)
for name, values in headers.items():
    for v in values:
        print(f"{name}: {v}")

# Print body
print("\n" + "=" * 50)
print("BODY")
print("=" * 50)
plain_text, html = get_body(msg)
print("--- Plain text ---")
print(plain_text)
print("\n--- HTML present? ---")
print("Yes" if html else "No")

# Print attachments
print("\n" + "=" * 50)
print("ATTACHMENTS")
print("=" * 50)
attachments = get_attachments(msg)
if attachments:
    for a in attachments:
        print(f"Filename: {a['filename']}, Type: {a['content_type']}")
else:
    print("None found")

# Test header forensics
from analyzer.header_forensics import analyze_headers

print("\n" + "=" * 50)
print("HEADER FORENSICS")
print("=" * 50)
results = analyze_headers(headers)
for check, result in results.items():
    print(f"{check}: {result}")

# Test SPF/DKIM/DMARC parsing
from analyzer.auth_checks import analyze_auth

print("\n" + "=" * 50)
print("AUTHENTICATION (SPF/DKIM/DMARC)")
print("=" * 50)
auth = analyze_auth(headers)
for k, v in auth.items():
    print(f"{k}: {v}")

# Test URL extraction
from analyzer.url_analysis import analyze_urls

print("\n" + "=" * 50)
print("URLS")
print("=" * 50)
url_results = analyze_urls(plain_text, html)
for u in url_results:
    print(f"Original: {u['original']}")
    print(f"Defanged: {u['defanged']}")
    print(f"Domain: {u['domain']}")
    print(f"Flags: {u['flags']}")
    print("-" * 30)

# Test attachment analysis + final risk score
from analyzer.attachment_analysis import analyze_attachments
from analyzer.risk_scorer import score_email

attachment_results = analyze_attachments(attachments)

print("\n" + "=" * 50)
print("RISK SCORE")
print("=" * 50)
verdict = score_email(results, auth, url_results, attachment_results)
print(f"Score: {verdict['score']}/100")
print(f"Level: {verdict['level']}")
print("Reasons:")
for r in verdict['reasons']:
    print(f"  - {r}")
