"""GrandmaGuard Main Flask Routes Module.

This module defines the core Flask web routes for the GrandmaGuard AI security scanning
application. It provides both web interface endpoints for human interaction and API
endpoints for programmatic access to scanning functionality.

Key Features:
    - Web Interface Routes: Dashboard, scan management, result visualization
    - REST API Endpoints: Results retrieval, manual review handling, data export
    - LLM Proxy Endpoint: Real-time AI safety scanning and response filtering
    - Runtime Monitoring: Logging and audit trail functionality

Route Categories:
    1. Web Interface Routes:
        - / : Main dashboard displaying test runs and results
        - /compare : Comparison interface for multiple test runs
        - /runtime-logs : View real-time scanning and security events
    
    2. API Endpoints:
        - /api/results/<run_id> : Retrieve detailed test results with charts
        - /api/review/<result_id> : Manual review and status updates
        - /api/export/<run_id> : CSV export functionality
    
    3. Proxy Endpoints:
        - /proxy/v1/chat/completions : OpenAI-compatible safety proxy

Data Flow:
    1. Users initiate scans via web interface (/run endpoint)
    2. Background scanner processes prompts and generates results
    3. Results are stored in database and displayed via API endpoints
    4. Manual review allows human oversight and status corrections
    5. Proxy endpoint provides real-time filtering for live applications

Security Features:
    - Real-time prompt injection detection
    - Multi-layer scanning with various AI safety tools
    - Manual review capability for edge cases
    - Comprehensive audit logging for compliance

Dependencies:
    - Flask: Web framework and request handling
    - SQLAlchemy: Database ORM for result persistence
    - Pandas: Data manipulation for exports
    - Scanner Engine: Background processing for security scans

Example:
    Start a new security scan:
    
    >>> POST /run
    >>> {
    ...     "scan_name": "Test Campaign",
    ...     "api_endpoint": "https://api.openai.com/v1/chat/completions",
    ...     "api_key": "sk-...",
    ...     "api_model_identifier": "gpt-3.5-turbo"
    ... }

Notes:
    - All routes include proper error handling and validation
    - Database sessions are managed automatically via Flask context
    - Proxy endpoint supports async processing for real-time filtering
    - Export functionality supports CSV format for external analysis
"""

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
    """Render the main dashboard page with recent test runs.
    
    Displays the GrandmaGuard dashboard showing all test runs ordered by
    most recent first. Provides navigation to view detailed results and
    start new scans.
    
    Returns:
        str: Rendered HTML template with test runs data
        
    Template Variables:
        runs (List[TestRun]): List of all test runs ordered by timestamp desc
    """
    runs = db_session.query(TestRun).order_by(TestRun.timestamp.desc()).all()
    return render_template("index.html", runs=runs)


@app.route("/run", methods=["POST"])
def run_new_scan():
    """Initiate a new AI security scan with specified parameters.
    
    Creates a new test run in the database and starts a background scanning
    thread to process security tests against the specified AI model endpoint.
    
    Form Parameters:
        scan_name (str): Human-readable name for the scan campaign
        api_model_identifier (str): Model identifier (e.g., "gpt-3.5-turbo")
        api_endpoint (str): Target API endpoint URL
        api_key (str): API key for authentication with target service
    
    Returns:
        Response: Redirect to index page on success, error message on failure
        
    Raises:
        400: If any required fields are missing
        
    Side Effects:
        - Creates new TestRun record in database
        - Starts background scanning thread
        - Redirects user to dashboard to monitor progress
    """
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
    """Retrieve detailed test results and analytics for a specific run.
    
    Returns comprehensive test results including aggregated statistics by OWASP
    category, chart data for visualization, and detailed individual test results.
    
    Args:
        run_id (int): Database ID of the test run to retrieve
        
    Returns:
        JSON: Structured response containing:
            - scan_name: Human-readable scan identifier
            - overall_score: Percentage of tests that passed (0.0-1.0)
            - chart_data: Chart.js compatible data for status visualization
            - detailed_results: Array of individual test results with metadata
            
    Response Format:
        {
            "scan_name": "Campaign Name",
            "overall_score": 0.85,
            "chart_data": {
                "labels": ["LLM01", "LLM02", ...],
                "datasets": [
                    {"label": "PASS", "data": [...], "backgroundColor": "..."},
                    {"label": "FAIL", "data": [...], "backgroundColor": "..."},
                    ...
                ]
            },
            "detailed_results": [
                {
                    "id": 123,
                    "owasp_category": "LLM01",
                    "status": "PASS",
                    "garak_status": "pass",
                    "llama_guard_status": "safe",
                    "judge_status": "approved",
                    "payload": "Test prompt...",
                    "response": "Model response..."
                },
                ...
            ]
        }
        
    Status Codes:
        200: Successful retrieval
        404: Test run not found
        
    Notes:
        - Chart data includes PASS, FAIL, PENDING_REVIEW, and ERROR statuses
        - Results are grouped by OWASP AI security categories
        - Overall score excludes pending/error results from calculation
    """
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
            "garak_status": r.garak_status,
            "llama_guard_status": r.llama_guard_status,
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
    """Handle manual review and status updates for individual test results.
    
    Allows human reviewers to override automated test results, useful for
    handling edge cases or false positives/negatives in AI safety detection.
    
    Args:
        result_id (int): Database ID of the test result to update
        
    JSON Parameters:
        status (str): New status, must be either "PASS" or "FAIL"
        
    Returns:
        JSON: Response indicating success/failure and updated metrics
        
    Response Format:
        {
            "success": true,
            "message": "Result 123 updated to PASS",
            "new_run_score": 0.87
        }
        
    Status Codes:
        200: Successfully updated
        400: Invalid status provided
        404: Test result not found
        
    Side Effects:
        - Updates individual test result status
        - Recalculates overall test run score
        - Commits changes to database
        
    Notes:
        - Only accepts "PASS" or "FAIL" statuses for human review
        - Overall score is recalculated excluding pending/error results
        - Changes are immediately persisted to database
    """
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
    """Render the test run comparison interface.
    
    Provides a web interface for comparing results between multiple test runs,
    allowing users to track improvements or regressions over time.
    
    Returns:
        str: Rendered HTML template with comparison interface
        
    Template Variables:
        runs (List[TestRun]): All available test runs for selection
        
    Notes:
        - Runs are ordered by most recent first for user convenience
        - Comparison logic is handled client-side via JavaScript
    """
    # Fetch all runs to populate the dropdowns, most recent first
    all_runs = db_session.query(TestRun).order_by(TestRun.timestamp.desc()).all()
    return render_template("compare.html", runs=all_runs)


@app.route("/api/export/<int:run_id>")
def export_csv(run_id):
    """Export test results to CSV format for external analysis.
    
    Generates a downloadable CSV file containing all test results for the
    specified run, suitable for import into spreadsheet applications or
    data analysis tools.
    
    Args:
        run_id (int): Database ID of the test run to export
        
    Returns:
        Response: CSV file download with appropriate headers
        
    CSV Columns:
        - Category: OWASP AI security category
        - Status: Final test result (PASS/FAIL/ERROR/PENDING_REVIEW)
        - Judge: AI judge assessment result
        - Payload: Original test prompt
        - Response: Model's response to the test prompt
        
    Status Codes:
        200: Successful export
        404: Test run not found
        
    Headers:
        - Content-Type: text/csv
        - Content-Disposition: attachment with filename pattern run_{id}_{name}.csv
        
    Notes:
        - Uses pandas for reliable CSV generation
        - Filename includes run ID and scan name for easy identification
        - All text fields are properly escaped for CSV format
    """
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
    """OpenAI-compatible proxy endpoint with real-time AI safety scanning.
    
    Acts as a drop-in replacement for OpenAI's chat completions API while
    providing real-time security scanning and response filtering. Intercepts
    requests, scans for security threats, and returns filtered responses.
    
    Request Format:
        Compatible with OpenAI chat completions API:
        {
            "model": "gpt-3.5-turbo",
            "messages": [
                {"role": "user", "content": "User prompt here"}
            ],
            ...
        }
    
    Returns:
        JSON: OpenAI-compatible response with security-filtered content
        
    Response Format:
        {
            "id": "chatcmpl-proxy-123",
            "object": "chat.completion",
            "created": 1234567890,
            "model": "gpt-3.5-turbo",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Filtered response content"
                },
                "finish_reason": "stop"
            }]
        }
    
    Environment Variables Required:
        TARGET_API_ENDPOINT: Downstream LLM API endpoint
        TARGET_LLM_API_KEY: API key for downstream service
        
    Status Codes:
        200: Successful processing and response
        400: Invalid request format or missing user prompt
        500: Server configuration error
        
    Security Features:
        - Real-time prompt injection detection
        - Multi-layer scanning (Garak, LlamaGuard, AI Judge)
        - Response filtering and sanitization
        - Comprehensive audit logging
        
    Notes:
        - Fully compatible with OpenAI API clients
        - Async processing for minimal latency impact
        - Transparent to end users while providing security
        - Uses environment configuration for target LLM routing
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
        "api_endpoint": os.getenv("TARGET_API_ENDPOINT"),
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


@app.route("/runtime-logs")
def runtime_logs_page():
    """Display recent runtime logs and security events.
    
    Provides a web interface for monitoring real-time security scanning
    activities, including proxy requests, scan results, and system events.
    
    Returns:
        str: Rendered HTML template with recent log entries
        
    Template Variables:
        logs (List[RuntimeLog]): Recent log entries (limited to 100 most recent)
        
    Notes:
        - Logs are ordered by most recent first
        - Limited to 100 entries for performance
        - Useful for debugging and monitoring security activity
        - Shows real-time scanning and proxy activities
    """
    logs = (
        db_session.query(RuntimeLog)
        .order_by(RuntimeLog.timestamp.desc())
        .limit(100)
        .all()
    )
    return render_template("runtime_logs.html", logs=logs)
