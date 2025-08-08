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
import traceback
import yaml
from datetime import datetime

import pandas as pd
from flask import Response, jsonify, redirect, render_template, request, url_for, flash, Blueprint, abort
from flask_login import login_user, logout_user, current_user, login_required

# Import the app and db_session created in __init__.py
from . import db_session

# In app/main.py
from .models import RuntimeLog, TestResult, TestRun
from .auth import User, users
from .scanner.runtime_scanner import scan_and_respond_in_realtime
# from .tasks import execute_full_scan  # Commented out - function doesn't exist

# A Blueprint is a way to organize a group of related views and other code.
# Instead of registering views and other code directly with an application,
# they are registered with a blueprint.
main = Blueprint('main', __name__)

# --- Routes ---

# Login Route
@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index')) # If already logged in, go to dashboard

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Find the user
        user_to_auth = None
        for user in users.values():
            if user.username == username:
                user_to_auth = user
                break
        
        # Check password and log them in
        if user_to_auth and user_to_auth.password == password:
            login_user(user_to_auth)
            # Redirect to the page they were trying to access, or the index
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.index'))
        else:
            flash('Invalid username or password. Please try again.')

    return render_template('login.html')

# Logout Route
@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))

@main.route("/")
@login_required
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


@main.route("/run", methods=["POST"])
@login_required
def run_new_scan():
    """
    Initiates a new security scan with support for multiple scan modes.
    """
    from .tasks import execute_scan_with_mode
    try:
        form_data = request.form
        scan_name = form_data.get("scan_name", "Untitled Scan")
        scan_mode = form_data.get("scan_mode", "payloads_only")  # NEW: scan mode selection
        
        # Validate scan mode
        valid_modes = ["payloads_only", "garak_only", "both"]
        if scan_mode not in valid_modes:
            flash(f"Invalid scan mode. Must be one of: {', '.join(valid_modes)}", "error")
            return redirect(url_for("main.index"))
        
        # API Configuration
        api_config = {
            "endpoint": form_data.get("api_endpoint"),
            "key": form_data.get("api_key"),
            "model_id": form_data.get("api_model_identifier")
        }
        
        if not all(api_config.values()):
            flash("Please provide API Endpoint, API Key, and Model Identifier.", "error")
            return redirect(url_for("main.index"))
        
        # LlamaGuard configuration
        llama_guard_soft_block = form_data.get('llama_guard_soft_block') == 'true'
        
        # Create new test run
        new_run = TestRun(scan_name=scan_name)
        db_session.add(new_run)
        db_session.commit()
        
        # Import here to avoid circular imports
        from .tasks import execute_scan_with_mode
        
        # Send task to background worker with scan mode
        execute_scan_with_mode.send(new_run.id, api_config, scan_mode, llama_guard_soft_block)
        
        mode_description = {
            "payloads_only": "existing payloads only",
            "garak_only": "garak probes only", 
            "both": "both existing payloads and garak probes"
        }
        
        flash(f"Started scan '{scan_name}' ({mode_description[scan_mode]}). Results will appear shortly.", "success")
        return redirect(url_for("main.index"))
        
    except Exception as e:
        print("!!!!!! A CRITICAL ERROR OCCURRED IN run_new_scan !!!!!!")
        print(f"ERROR TYPE: {type(e).__name__}")
        print(f"ERROR DETAILS: {e}")
        print("\n--- FULL TRACEBACK ---")
        import traceback
        traceback.print_exc()
        print("="*50 + "\n")
        
        flash("An error occurred while starting the scan. Please check the logs.", "error")
        return redirect(url_for("main.index"))


@main.route("/api/results/<int:run_id>")
@login_required
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
            "judge_status": "FAIL" if r.assessment_details and isinstance(r.assessment_details, list) and any(t.get('is_undesirable') for t in r.assessment_details) else ("PASS" if r.assessment_details else "N/A"),
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


@main.route("/api/review/<int:result_id>", methods=["POST"])
@login_required
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


@main.route("/compare")
@login_required
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


@main.route("/api/export/<int:run_id>")
@login_required
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
            "Judge": "FAIL" if r.assessment_details and any(t.get('is_undesirable') for t in r.assessment_details) else ("PASS" if r.assessment_details else "N/A"),
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


@main.route("/api/export/<int:run_id>/pdf")
@login_required
def export_pdf(run_id):
    """Export Red Team Report to a professional PDF format.
    
    Generates a comprehensive, formatted PDF report containing all test results,
    diagnostic analysis, and security assessments for the specified run.
    
    Args:
        run_id (int): Database ID of the test run to export
        
    Returns:
        Response: PDF file download with appropriate headers
        
    PDF Contents:
        - Executive Summary with key metrics
        - Detailed Security Analysis Breakdown
        - Individual Test Case Results with diagnostic information
        - Turn-by-turn conversation assessments
        - Risk factor analysis and recommendations
        
    Status Codes:
        200: Successful PDF generation and download
        404: Test run not found
        500: PDF generation error
        
    Headers:
        - Content-Type: application/pdf
        - Content-Disposition: attachment with filename pattern RedTeamReport_run_{id}_{name}.pdf
        
    Notes:
        - Uses WeasyPrint for professional PDF generation
        - Includes company branding and professional styling
        - Preserves color coding and diagnostic information
        - Suitable for executive reporting and compliance documentation
    """
    try:
        # Get the current run and previous run data (reuse logic from red_team_report)
        current_run = db_session.query(TestRun).filter_by(id=run_id).first()
        if not current_run:
            return "Run not found", 404

        previous_run = db_session.query(TestRun).filter(
            TestRun.timestamp < current_run.timestamp
        ).order_by(TestRun.timestamp.desc()).first()

        # Create a lookup for the previous run's results
        previous_results_lookup = {}
        if previous_run:
            for prev_result in previous_run.results:
                if prev_result.assessment_details:
                    initial_payload_key = prev_result.payload.split('\n---')[0]
                    if initial_payload_key:
                        previous_results_lookup[initial_payload_key] = prev_result

        # Generate report data with diagnostic analysis
        from .scanner.diagnostic_analyzer import DiagnosticAnalyzer
        diagnostic_analyzer = DiagnosticAnalyzer()
        report_data = []
        
        for result in current_run.results:
            if not result.assessment_details:
                continue
                
            initial_payload_key = result.payload.split('\n---')[0]
            
            # Generate diagnostic analysis
            diagnostic_info = None
            if hasattr(result, 'llama_guard_status') and hasattr(result, 'garak_status'):
                # Parse garak_status back to risk_profile format
                risk_profile = {}
                if result.garak_status and ':' in result.garak_status:
                    detector, score_str = result.garak_status.split(':')
                    try:
                        risk_profile[detector] = float(score_str)
                    except ValueError:
                        risk_profile = {}
                
                diagnostic_info = diagnostic_analyzer.generate_diagnostic_report(
                    result.assessment_details,
                    result.llama_guard_status or {},
                    risk_profile,
                    result.status
                )
            
            # Regression analysis
            regression_status = "NO_CHANGE"
            prev_result_obj = previous_results_lookup.get(initial_payload_key)

            current_test_passed = not any(t.get('is_undesirable') for t in result.assessment_details)

            if prev_result_obj:
                previous_test_passed = not any(t.get('is_undesirable') for t in prev_result_obj.assessment_details)
                
                if not current_test_passed and previous_test_passed:
                    regression_status = "REGRESSION"
                elif current_test_passed and not previous_test_passed:
                    regression_status = "IMPROVEMENT"

            report_data.append({
                'result_obj': result,
                'regression_status': regression_status,
                'initial_payload': initial_payload_key,
                'diagnostic_info': diagnostic_info
            })

        # Render the PDF template
        html_content = render_template(
            'pdf_report.html',
            run=current_run,
            report_data=report_data,
            previous_run=previous_run
        )
        
        # Generate PDF
        import weasyprint
        from io import BytesIO
        
        pdf_buffer = BytesIO()
        weasyprint.HTML(string=html_content, base_url=request.url_root).write_pdf(pdf_buffer)
        pdf_buffer.seek(0)
        
        # Create response
        response = Response(
            pdf_buffer.read(),
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename=RedTeamReport_run_{run_id}_{current_run.scan_name}.pdf'
            }
        )
        
        return response
        
    except Exception as e:
        print(f"PDF generation error: {e}")
        import traceback
        traceback.print_exc()
        return f"Error generating PDF: {str(e)}", 500


# --- THE LLM FIREWALL/PROXY ENDPOINT ---
@main.route("/proxy/v1/chat/completions", methods=["POST"])
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


@main.route("/runtime-logs")
@login_required
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

@main.route('/report/redteam/<int:run_id>')
@login_required
def red_team_report(run_id):
    """
    Enhanced Red Team Report: Shows both user-defined assessment criteria 
    AND technical security analysis with diagnostic explanations.
    """
    from .scanner.diagnostic_analyzer import DiagnosticAnalyzer
    
    current_run = db_session.query(TestRun).filter_by(id=run_id).first()
    if not current_run:
        abort(404)

    previous_run = db_session.query(TestRun).filter(
        TestRun.timestamp < current_run.timestamp
    ).order_by(TestRun.timestamp.desc()).first()

    # Create a lookup for the previous run's results.
    previous_results_lookup = {}
    if previous_run:
        for prev_result in previous_run.results:
            if prev_result.assessment_details: # Only consider red team results
                initial_payload_key = prev_result.payload.split('\n---')[0]
                if initial_payload_key:
                    previous_results_lookup[initial_payload_key] = prev_result

    diagnostic_analyzer = DiagnosticAnalyzer()
    report_data = []
    
    for result in current_run.results:
        if not result.assessment_details:
            continue
            
        initial_payload_key = result.payload.split('\n---')[0]
        
        # Generate diagnostic analysis
        diagnostic_info = None
        if hasattr(result, 'llama_guard_status') and hasattr(result, 'garak_status'):
            # Parse garak_status back to risk_profile format
            risk_profile = {}
            if result.garak_status and ':' in result.garak_status:
                detector, score_str = result.garak_status.split(':')
                try:
                    risk_profile[detector] = float(score_str)
                except ValueError:
                    risk_profile = {}
            
            diagnostic_info = diagnostic_analyzer.generate_diagnostic_report(
                result.assessment_details,
                result.llama_guard_status or {},
                risk_profile,
                result.status
            )
        
        # Regression analysis
        regression_status = "NO_CHANGE"
        prev_result_obj = previous_results_lookup.get(initial_payload_key)

        current_test_passed = not any(t.get('is_undesirable') for t in result.assessment_details)

        if prev_result_obj:
            previous_test_passed = not any(t.get('is_undesirable') for t in prev_result_obj.assessment_details)
            
            if not current_test_passed and previous_test_passed:
                regression_status = "REGRESSION"
            elif current_test_passed and not previous_test_passed:
                regression_status = "IMPROVEMENT"

        report_data.append({
            'result_obj': result,
            'regression_status': regression_status,
            'initial_payload': initial_payload_key,
            'diagnostic_info': diagnostic_info  # NEW: Add diagnostic analysis
        })
        
    return render_template(
        "red_team_report.html", 
        run=current_run, 
        report_data=report_data,
        previous_run=previous_run
    )
    
@main.route("/run-single-test", methods=["POST"])
@login_required
def run_single_test():
    form_data = request.form
    save_option = form_data.get("save_option")
    test_name = form_data.get("test_name", "Unnamed Live Test")
    
    # --- 1. Build the Test Case Data from the form ---
    follow_ups = form_data.getlist('follow_up_payloads')
    test_case_data = {
        "category": form_data.get("category", "Ad-Hoc Test"),
        "payload": form_data.get("payload", ""),
        "follow_up_payloads": [f for f in follow_ups if f.strip()],
    }
    undesirable_outcome = form_data.get("undesirable_outcome", "")
    if undesirable_outcome.strip():
        test_case_data["undesirable_outcome"] = undesirable_outcome.strip()
        test_case_data["desired_outcome"] = form_data.get("desired_outcome", "").strip()
    
    # --- 2. Handle the 'Permanent' Save Option ---
    if save_option == "permanent":
        # This logic is correct and remains unchanged.
        payloads_file = "app/scanner/payloads.yml"
        try:
            with open(payloads_file, 'r') as f:
                payloads = yaml.safe_load(f) or {}
            
            new_key = test_name.lower().replace(' ', '_').replace('-', '_')
            timestamp = datetime.now().strftime("%S")
            new_key = f"{new_key}_{timestamp}"
            payloads[new_key] = test_case_data
            
            with open(payloads_file, 'w') as f:
                yaml.dump(payloads, f, sort_keys=False, indent=2)
            
            flash(f"Successfully added new payload '{test_name}' (key: {new_key}) to payloads.yml!", "success")
        except Exception as e:
            flash(f"Error saving to payloads.yml: {e}", "error")
        
        return redirect(url_for("main.index"))

    # --- 3. Handle the 'Temporary' Run Option ---
    elif save_option == "temporary":
        # --- THIS IS THE FIX ---
        # We need a new, dedicated task for single ad-hoc tests.
        # It's cleaner than trying to reuse the main scan task.
        from .tasks import execute_ad_hoc_test

        api_config = {
            "endpoint": form_data.get("live_test_api_endpoint"),
            "key": form_data.get("live_test_api_key"),
            "model_id": form_data.get("live_test_model_identifier")
        }
        llama_guard_soft_block = form_data.get('live_test_soft_block') == 'true'
        
        if not all(api_config.values()):
            flash("For a temporary test, you must provide the Model, Endpoint, and API Key.", "error")
            return redirect(url_for("main.index"))

        scan_name = f"Temporary Test: {test_name}"
        new_run = TestRun(scan_name=scan_name)
        db_session.add(new_run)
        db_session.commit()

        # Send the single test case and config to the new dedicated task.
        execute_ad_hoc_test.send(
            new_run.id, 
            test_case_data, 
            api_config, 
            llama_guard_soft_block
        )
        # --- END OF FIX ---

        flash(f"Started temporary scan '{scan_name}'. Results will appear shortly.", "success")
        return redirect(url_for("main.index"))

    flash("Invalid save option selected.", "error")
    return redirect(url_for("main.index"))


@main.route('/report/garak/<int:run_id>')
@login_required
def garak_report(run_id):
    """Displays a detailed report for a Garak scan."""
    # --- THIS IS THE FIX ---
    test_run = db_session.query(TestRun).filter_by(id=run_id).first()
    if not test_run:
        abort(404)
    # --- END OF FIX ---
    
    garak_results = [r for r in test_run.results if r.owasp_category.startswith("GARAK_")]
    
    return render_template("garak_report.html", run=test_run, results=garak_results)