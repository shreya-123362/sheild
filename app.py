"""
app.py
SHEILD web interface - Flask app.
Lets you upload an .eml file, analyzes it, saves the result as a
case, shows a browsable history of past scans, and tracks badges.
"""

from flask import Flask, render_template, request, redirect, url_for
import os

from cli import analyze_email_file
from analyzer.case_storage import save_case, load_case, list_cases
from analyzer.badges import get_earned_badges, get_next_badge

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


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


if __name__ == "__main__":
    app.run(debug=True)
