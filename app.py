"""
app.py
------
Flask web interface for the Phishing Awareness Analysis tool.

Notice this file does NOT reimplement any detection logic - it only
imports and calls the same analyzer.py, email_auth.py, threat_intel.py,
and report_generator.py modules that main.py (the CLI) uses. This is
the payoff of keeping detection logic separate from the interface:
adding a second interface (web) required zero changes to the "brain"
of the tool.
"""

import os

from flask import Flask, render_template, request

from report_generator import combine_findings

app = Flask(__name__)

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")


@app.route("/")
def index():
    """Home page: paste-an-email console."""
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """Run analysis on pasted email text and show the report."""
    raw_email = request.form.get("raw_email", "")
    result = combine_findings(raw_email)
    return render_template("result.html", result=result, case_id="manual-input")


@app.route("/sample/<filename>")
def analyze_sample(filename):
    """Run analysis on one specific sample file and show the report."""
    path = os.path.join(SAMPLES_DIR, filename)

    if not os.path.isfile(path):
        return f"Sample not found: {filename}", 404

    with open(path, "r", encoding="utf-8") as f:
        raw_email = f.read()

    result = combine_findings(raw_email)
    return render_template("result.html", result=result, case_id=filename)


@app.route("/batch")
def batch():
    """Analyze every sample and show a triage-queue style table."""
    if not os.path.isdir(SAMPLES_DIR):
        return render_template("batch.html", rows=[])

    sample_files = sorted(f for f in os.listdir(SAMPLES_DIR) if f.endswith(".txt"))

    rows = []
    for filename in sample_files:
        path = os.path.join(SAMPLES_DIR, filename)
        with open(path, "r", encoding="utf-8") as f:
            raw_email = f.read()
        result = combine_findings(raw_email)
        rows.append({
            "filename": filename,
            "verdict": result["final_verdict"],
            "score": result["total_score"],
        })

    return render_template("batch.html", rows=rows)


if __name__ == "__main__":
    app.run(debug=True)
