"""
app.py
SHEILD web interface - Flask app.
Lets you upload an .eml file, analyzes it, saves the result as a
case, shows a browsable history of past scans, tracks badges,
lets you compare two past cases side by side, and offers a
"Wall of Shame" gallery of pre-loaded sample cases for instant demoing.
"""

from flask import Flask, render_template, request, redirect, url_for
import os

from cli import analyze_email_file
from analyzer.case_storage import save_case, load_case, list_cases
from analyzer.badges import get_earned_badges, get_next_badge

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Pre-loaded sample emails for the Wall of Shame gallery.
# Each entry: (filename in samples/, short label shown on the gallery page)
GALLERY_SAMPLES = [
    ("example.eml", "Fake PayPal Account Suspension"),
    ("legit_example.eml", "Legitimate GitHub Notification"),
    ("borderline_example.eml", "Spotify Marketing Email (Borderline)"),
]


@app.route("/", methods=["GET", "POST"])
def index():
    """
    GET: show the upload form
    POST: analyze the uploaded file, save it as a case, redirect to its report page
    """
    if request.method == "POST":
        file = request.files.get("email_file")

        if not file or file.filename == "":
            return render_template("index.html", error="No file selected")

        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)

        result = analyze_email_file(filepath)
        case_id = save_case(result)

        return redirect(url_for("view_case", case_id=case_id))

    return render_template("index.html")


@app.route("/case/<case_id>")
def view_case(case_id):
    """
    Shows the full report for one saved case, looked up by its ID.
    """
    case = load_case(case_id)
    if not case:
        return "Case not found", 404

    return render_template("result.html", result=case["full_result"], case_id=case_id)


@app.route("/history")
def history():
    """
    Shows a list of all past scans, newest first, plus earned badges.
    """
    cases = list_cases()
    total = len(cases)
    earned = get_earned_badges(total)
    next_badge = get_next_badge(total)

    return render_template(
        "history.html",
        cases=cases,
        total=total,
        earned_badges=earned,
        next_badge=next_badge,
    )


@app.route("/compare", methods=["GET", "POST"])
def compare():
    """
    GET: show a form to pick two cases to compare (or two IDs via query params)
    POST: show both cases side by side
    """
    cases = list_cases()

    case_a_id = request.values.get("case_a")
    case_b_id = request.values.get("case_b")

    if case_a_id and case_b_id:
        case_a = load_case(case_a_id)
        case_b = load_case(case_b_id)

        if not case_a or not case_b:
            return "One or both cases not found", 404

        return render_template(
            "compare.html",
            case_a=case_a["full_result"],
            case_b=case_b["full_result"],
        )

    return render_template("compare_select.html", cases=cases)


@app.route("/gallery")
def gallery():
    """
    Wall of Shame - shows a curated list of pre-loaded sample emails
    so visitors can see SHEILD in action without uploading anything.
    """
    return render_template("gallery.html", samples=GALLERY_SAMPLES)


@app.route("/gallery/<filename>")
def view_gallery_sample(filename):
    """
    Analyzes one specific pre-loaded sample on the fly and shows the
    full report - same template as a real uploaded case.
    """
    # Only allow filenames that are actually in our approved gallery list -
    # prevents someone from tampering with the URL to read arbitrary files
    allowed_filenames = [f for f, label in GALLERY_SAMPLES]
    if filename not in allowed_filenames:
        return "Sample not found", 404

    filepath = os.path.join("samples", filename)
    result = analyze_email_file(filepath)

    return render_template("result.html", result=result, case_id=None)


if __name__ == "__main__":
    app.run(debug=True)
