#!/usr/bin/env python3
"""
cli.py
SHEILD - Phishing Email Analyzer
Command-line entry point: takes an .eml file and prints a risk report.
"""

import argparse
import sys

from analyzer.parser import load_email, get_headers, get_body, get_attachments
from analyzer.header_forensics import analyze_headers
from analyzer.auth_checks import analyze_auth
from analyzer.url_analysis import analyze_urls
from analyzer.attachment_analysis import analyze_attachments
from analyzer.risk_scorer import score_email


def analyze_email_file(filepath):
    """
    Runs the full SHEILD pipeline on one .eml file.
    This is the same sequence we built and tested piece by piece -
    now it's one function, callable from anywhere (CLI today, web UI later).
    """
    msg = load_email(filepath)

    headers = get_headers(msg)
    plain_text, html = get_body(msg)
    attachments = get_attachments(msg)

    header_results = analyze_headers(headers)
    auth_results = analyze_auth(headers)
    url_results = analyze_urls(plain_text, html)
    attachment_results = analyze_attachments(attachments)

    verdict = score_email(header_results, auth_results, url_results, attachment_results)

    return {
        "headers": headers,
        "header_forensics": header_results,
        "auth": auth_results,
        "urls": url_results,
        "attachments": attachment_results,
        "verdict": verdict,
    }


def main():
    # argparse auto-generates --help, handles missing/invalid arguments,
    # and gives clean error messages - all for free, no extra code needed
    parser = argparse.ArgumentParser(
        description="SHEILD - Phishing Email Analyzer"
    )
    parser.add_argument(
        "filepath",
        help="Path to the .eml file to analyze"
    )
    args = parser.parse_args()

    try:
        result = analyze_email_file(args.filepath)
    except FileNotFoundError:
        print(f"Error: file not found: {args.filepath}")
        sys.exit(1)

    print_report(result)


def print_report(result):
    """
    Prints a clean, readable report to the terminal.
    """
    print("=" * 55)
    print("SHEILD - Phishing Email Analysis Report")
    print("=" * 55)

    from_header = result["headers"].get("From", ["Unknown"])[0]
    subject = result["headers"].get("Subject", ["(no subject)"])[0]
    print(f"From: {from_header}")
    print(f"Subject: {subject}")

    print("\n--- Header Forensics ---")
    hf = result["header_forensics"]
    print(f"From/Reply-To mismatch: {hf['from_reply_mismatch']['mismatch']}")
    print(f"From/Return-Path mismatch: {hf['from_returnpath_mismatch']['mismatch']}")
    print(f"Brand impersonation: {hf['brand_impersonation']['impersonation']}")

    print("\n--- Authentication ---")
    auth = result["auth"]
    print(f"SPF: {auth['spf']} | DKIM: {auth['dkim']} | DMARC: {auth['dmarc']}")

    print("\n--- URLs Found ---")
    if result["urls"]:
        for u in result["urls"]:
            flag_text = f" [FLAGGED: {', '.join(u['flags'])}]" if u["flags"] else ""
            print(f"  {u['defanged']}{flag_text}")
    else:
        print("  None found")

    print("\n--- Attachments ---")
    if result["attachments"]:
        for a in result["attachments"]:
            print(f"  {a['filename']} ({a['content_type']}, {a['size_bytes']} bytes)")
            if a["hashes"]:
                print(f"    SHA256: {a['hashes']['sha256']}")
            if a["dangerous_extension"]:
                print(f"    WARNING: dangerous file extension")
    else:
        print("  None found")

    print("\n" + "=" * 55)
    verdict = result["verdict"]
    print(f"VERDICT: {verdict['level']} ({verdict['score']}/100)")
    print("=" * 55)
    if verdict["reasons"]:
        print("Reasons:")
        for r in verdict["reasons"]:
            print(f"  - {r}")


if __name__ == "__main__":
    main()
