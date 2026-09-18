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
