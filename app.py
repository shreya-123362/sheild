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

GALLERY_SAMPLES = [
    ("example.eml", "Fake PayPal Account Suspension"),
    ("legit_example.eml", "Legitimate GitHub Notification"),
    ("borderline_example.eml", "Spotify Marketing Email (Borderline)"),
]


@app.route("/", methods=["GET", "POST"])
def index():
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
    case = load_case(case_id)
    if not case:
        return "Case not found", 404

    return render_template("result.html", result=case["full_result"], case_id=case_id)


@app.route("/history")
def history():
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
    return render_template("gallery.html", samples=GALLERY_SAMPLES)


@app.route("/gallery/<filename>")
def view_gallery_sample(filename):
    allowed_filenames = [f for f, label in GALLERY_SAMPLES]
    if filename not in allowed_filenames:
        return "Sample not found", 404

    filepath = os.path.join("samples", filename)
    result = analyze_email_file(filepath)

    return render_template("result.html", result=result, case_id=None)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
