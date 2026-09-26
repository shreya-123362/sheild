# SHEILD

**Phishing email analyzer with header forensics, authentication checks, and risk scoring.**

Live demo: https://sheild-5xpu.onrender.com

SHEILD takes a raw `.eml` email file and produces a scored, evidence-backed verdict on whether it's phishing — the same kind of analysis a SOC (Security Operations Center) Tier-1 analyst performs manually when triaging suspicious emails.

## Why

Phishing triage is one of the most common day-to-day tasks in a SOC. Instead of just reading about the process, I built a tool that actually performs it: parsing raw email headers, verifying sender authentication, catching brand impersonation and lookalike domains, hashing attachments, and scoring the combined evidence into a clear verdict.

## Features

- **Header forensics** — detects From/Reply-To and From/Return-Path domain mismatches, and brand impersonation in display names (e.g. "PayPal" name with a non-PayPal domain)
- **SPF / DKIM / DMARC parsing** — verifies whether the sending server was actually authorized to send as that domain
- **URL analysis** — extracts and defangs links, flags raw-IP URLs, excessive subdomains, and lookalike/typosquatted domains (e.g. `paypa1.com` vs `paypal.com`)
- **Attachment hashing** — computes MD5/SHA1/SHA256 hashes and flags dangerous file extensions, without ever executing the file
- **Content analysis** — detects urgency language, threat language, and generic greetings commonly used in social engineering
- **Weighted risk scoring** — combines all signals into a 0-100 score and a Low/Medium/High/Critical verdict, with technical signals weighted more heavily than fuzzy linguistic ones
- **Case history** — every scan is saved and browsable later
- **Compare mode** — view two past cases side by side
- **Wall of Shame gallery** — pre-loaded sample emails for instant demoing, no upload required
- **CLI and web UI** — same detection engine powers both, built modularly so new checks can be added without touching existing code

## Validation

Tested against three deliberately different samples to confirm the scorer discriminates correctly, not just flags everything:

| Sample | Result |
|---|---|
| Fake PayPal phishing email (spoofed domain, failed auth, urgency language) | **Critical (100/100)** |
| Legitimate GitHub notification (passing auth, matching domains) | **Low (0/100)** |
| Legitimate marketing email with mild urgency language only | **Low (5/100)** |

## Tech stack

Python 3, Flask, Jinja2, Gunicorn. No external APIs or paid services required — hosted on Render's free tier.

## Running locally

```bash
git clone https://github.com/shreya-123362/sheild.git
cd sheild
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Then open `http://127.0.0.1:5000`.

Or use the CLI directly:
```bash
python3 cli.py samples/example.eml
```

## Architecture

Each analysis module (`analyzer/parser.py`, `header_forensics.py`, `auth_checks.py`, `url_analysis.py`, `attachment_analysis.py`, `content_analysis.py`) is independent and returns structured findings. `risk_scorer.py` combines all of them into one weighted verdict. Both `cli.py` and `app.py` call the same core pipeline (`analyze_email_file()`), so the CLI and web UI never fall out of sync, and adding a new detection module only requires adding one file plus one scoring rule.

## Known limitations

- Case history is stored as local JSON files, which don't persist across free-tier hosting restarts — a production version would use a real database
- No live threat intelligence lookups (VirusTotal, etc.) yet — attachment/URL analysis is currently local-only
- Brand/lookalike detection lists are a curated starter set, not exhaustive

## Author

Built by Shreya Ganesh, cybersecurity student.
