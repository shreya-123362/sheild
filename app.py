"""
app.py
SHEILD web interface - Flask app.
Lets you upload an .eml file in a browser and see the analysis report.
"""

from flask import Flask, render_template, request
import os

from cli import analyze_email_file

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route("/", methods=["GET", "POST"])
def index():
    """
    GET: show the upload form
    POST: someone submitted a file - analyze it, show results
    """
    if request.method == "POST":
        file = request.files.get("email_file")

        if not file or file.filename == "":
            return render_template("index.html", error="No file selected")

        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)

        result = analyze_email_file(filepath)

        return render_template("result.html", result=result)

    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)

