"""
case_storage.py
Saves and retrieves past scan results as JSON files, so the web UI
can show a history of previous analyses instead of losing them
the moment you navigate away.
"""

import json
import os
import uuid
from datetime import datetime

HISTORY_DIR = "history"


def save_case(result):
    """
    Saves one analysis result to disk as a JSON file.
    Generates a unique case ID and timestamp, then returns the ID
    so the caller (app.py) can redirect to a page showing this exact case.
    """
    os.makedirs(HISTORY_DIR, exist_ok=True)

    case_id = str(uuid.uuid4())[:8]
    timestamp = datetime.now().isoformat()

    from_header = result["headers"].get("From", ["Unknown"])[0]
    subject = result["headers"].get("Subject", ["(no subject)"])[0]

    case_data = {
        "id": case_id,
        "timestamp": timestamp,
        "from": from_header,
        "subject": subject,
        "score": result["verdict"]["score"],
        "level": result["verdict"]["level"],
        "full_result": result,
    }

    filepath = os.path.join(HISTORY_DIR, f"{case_id}.json")
    with open(filepath, "w") as f:
        json.dump(case_data, f, indent=2)

    return case_id


def load_case(case_id):
    """
    Loads one saved case by its ID. Returns None if it doesn't exist.
    """
    filepath = os.path.join(HISTORY_DIR, f"{case_id}.json")
    if not os.path.exists(filepath):
        return None

    with open(filepath, "r") as f:
        return json.load(f)


def list_cases():
    """
    Returns a summary list of all saved cases, newest first.
    """
    if not os.path.exists(HISTORY_DIR):
        return []

    cases = []
    for filename in os.listdir(HISTORY_DIR):
        if filename.endswith(".json"):
            filepath = os.path.join(HISTORY_DIR, filename)
            with open(filepath, "r") as f:
                data = json.load(f)
                cases.append({
                    "id": data["id"],
                    "timestamp": data["timestamp"],
                    "from": data["from"],
                    "subject": data["subject"],
                    "score": data["score"],
                    "level": data["level"],
                })

    cases.sort(key=lambda c: c["timestamp"], reverse=True)
    return cases
