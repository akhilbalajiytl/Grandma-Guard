# app/main.py
import os

import pandas as pd
from flask import Response, jsonify, redirect, render_template, request, url_for

# Import the app and db_session created in __init__.py
from . import app, db_session

# In app/main.py
from .models import RuntimeLog, TestResult, TestRun
from .scanner.engine import start_scan_thread
from .scanner.runtime_scanner import scan_and_respond_in_realtime


# --- Routes ---
@app.route("/")
def index():
    runs = db_session.query(TestRun).order_by(TestRun.timestamp.desc()).all()
    return render_template("index.html", runs=runs)


@app.route("/run", methods=["POST"])
def run_new_scan():
    scan_name = request.form["scan_name"]
    api_model_identifier = request.form["api_model_identifier"]
    api_endpoint = request.form["api_endpoint"]

    # GET THE KEY FROM THE WEB FORM
    api_key = request.form["api_key"]

    if not all([scan_name, api_model_identifier, api_endpoint, api_key]):
        return "Error: All fields are required.", 400

    new_run = TestRun(scan_name=scan_name)
    db_session.add(new_run)
    db_session.commit()

    # Pass the key from the form to the scanner
    start_scan_thread(
        new_run.id, scan_name, api_endpoint, api_key, api_model_identifier
    )

    return redirect(url_for("index"))


@app.route("/api/results/<int:run_id>")
def api_results(run_id):
    run = db_session.query(TestRun).get(run_id)
    if not run:
        return jsonify({"error": "Run not found"}), 404

    results_by_owasp = {}
    # Define all possible statuses we want to count for the chart
    valid_chart_statuses = ["PASS", "FAIL", "ERROR", "PENDING_REVIEW"]

    for result in run.results:
        cat = result.owasp_category
        if cat not in results_by_owasp:
            # Initialize the dictionary for this category with all possible statuses set to 0
            results_by_owasp[cat] = {status: 0 for status in valid_chart_statuses}

        # Safely increment the count for the result's status
        if result.status in results_by_owasp[cat]:
            results_by_owasp[cat][result.status] += 1

    # Now, build the datasets for the chart
    chart_data = {
        "labels": list(results_by_owasp.keys()),
        "datasets": [
            {
                "label": "PASS",
                "data": [v.get("PASS", 0) for v in results_by_owasp.values()],
                "backgroundColor": "rgba(39, 174, 96, 0.7)",  # Use a slightly more solid color for charts
            },
            {
                "label": "FAIL",
                "data": [v.get("FAIL", 0) for v in results_by_owasp.values()],
                "backgroundColor": "rgba(192, 57, 43, 0.7)",
            },
            {
                "label": "PENDING",
                "data": [v.get("PENDING_REVIEW", 0) for v in results_by_owasp.values()],
                "backgroundColor": "rgba(241, 196, 15, 0.7)",
            },
            {
                "label": "ERROR",
                "data": [v.get("ERROR", 0) for v in results_by_owasp.values()],
                "backgroundColor": "rgba(128, 128, 128, 0.7)",
            },
        ],
    }

    # Add 'garak_status' to the detailed results payload
    detailed_results = [
        {
            "id": r.id,
            "owasp_category": r.owasp_category,
            "status": r.status,
            # baseline_status": r.baseline_status,
            "garak_status": r.garak_status,  # <-- ADD THIS LINE
            "judge_status": r.judge_status,
            "payload": r.payload,
            "response": r.response,
        }
        for r in run.results
    ]

    return jsonify(
        {
            "scan_name": run.scan_name,
            "overall_score": run.overall_score,
            "chart_data": chart_data,
            "detailed_results": detailed_results,
        }
    )


@app.route("/api/review/<int:result_id>", methods=["POST"])
def handle_review(result_id):
    data = request.get_json()
    new_status = data.get("status")

    if not new_status or new_status not in ["PASS", "FAIL"]:
        return jsonify({"error": "Invalid status provided."}), 400

    result = db_session.query(TestResult).filter_by(id=result_id).first()
    if not result:
        return jsonify({"error": "Test result not found."}), 404

    # Update the status with the human's verdict
    result.status = new_status

    # We also need to recalculate the overall score for the test run
    run = result.run
    # total_tests = len(run.results)
    # Exclude non-final statuses from the pass calculation
    final_results = [r for r in run.results if r.status in ["PASS", "FAIL"]]
    passed_tests = sum(1 for r in final_results if r.status == "PASS")

    if len(final_results) > 0:
        run.overall_score = passed_tests / len(final_results)
    else:
        run.overall_score = 0  # Avoid division by zero if all are pending/error

    db_session.commit()

    return jsonify(
        {
            "success": True,
            "message": f"Result {result_id} updated to {new_status}",
            "new_run_score": run.overall_score,
        }
    )


@app.route("/compare")
def compare_page():
    # Fetch all runs to populate the dropdowns, most recent first
    all_runs = db_session.query(TestRun).order_by(TestRun.timestamp.desc()).all()
    return render_template("compare.html", runs=all_runs)


@app.route("/api/export/<int:run_id>")
def export_csv(run_id):
    run = db_session.query(TestRun).get(run_id)
    if not run:
        return "Run not found", 404

    # Convert results to a list of dictionaries
    data = [
        {
            "Category": r.owasp_category,
            "Status": r.status,
            # "Baseline": r.baseline_status,
            "Judge": r.judge_status,
            "Payload": r.payload,
            "Response": r.response,
        }
        for r in run.results
    ]

    # Create a pandas DataFrame
    df = pd.DataFrame(data)

    # Generate CSV in memory
    csv_output = df.to_csv(index=False)

    return Response(
        csv_output,
        mimetype="text/csv",
        headers={
            "Content-disposition": f"attachment; filename=run_{run_id}_{run.scan_name}.csv"
        },
    )


# --- THE LLM FIREWALL/PROXY ENDPOINT ---
@app.route("/proxy/v1/chat/completions", methods=["POST"])
async def proxy_chat_completions():
    """
    This endpoint acts as a drop-in replacement for the OpenAI API.
    It intercepts the request, scans it, and then returns a response.
    """
    request_data = request.get_json()
    if not request_data or "messages" not in request_data:
        return jsonify({"error": "Invalid request body"}), 400

    # Extract the user's prompt
    user_prompt = ""
    for message in request_data["messages"]:
        if message.get("role") == "user":
            user_prompt = message.get("content")
            break

    if not user_prompt:
        return jsonify({"error": "No user prompt found"}), 400

    # For now, I am using environment variables for the target LLM.
    model_config = {
        "api_endpoint": os.getenv(
            "TARGET_API_ENDPOINT", "https://api.openai.com/v1/chat/completions"
        ),
        "api_key": os.getenv("TARGET_LLM_API_KEY"),
        "model_identifier": request_data.get(
            "model", "gpt-3.5-turbo"
        ),  # Use model from request or a default
    }

    if not model_config["api_key"]:
        return jsonify({"error": "TARGET_LLM_API_KEY not configured on server"}), 500

    # Call our runtime scanner to do the work
    final_response_content = await scan_and_respond_in_realtime(
        user_prompt, model_config
    )

    # Return the response in a format that mimics the OpenAI API
    return jsonify(
        {
            "id": "chatcmpl-proxy-123",
            "object": "chat.completion",
            "created": int(os.path.getmtime(os.path.abspath(os.path.curdir))),
            "model": model_config["model_identifier"],
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": final_response_content,
                    },
                    "finish_reason": "stop",
                }
            ],
        }
    )


# --- NEW: A simple page to view the runtime logs ---
@app.route("/runtime-logs")
def runtime_logs_page():
    logs = (
        db_session.query(RuntimeLog)
        .order_by(RuntimeLog.timestamp.desc())
        .limit(100)
        .all()
    )
    return render_template("runtime_logs.html", logs=logs)
