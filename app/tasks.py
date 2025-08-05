"""GrandmaGuard Background Task Processing Module.

This module provides asynchronous background task processing capabilities for
computationally intensive security analysis operations using the Dramatiq
task queue framework with Redis as the message broker.

The background task system is designed to handle time-consuming forensic
analysis operations that would otherwise block the main web application,
ensuring responsive user experience while maintaining comprehensive security
analysis capabilities.

Key Features:
    - Asynchronous forensic analysis processing
    - Redis-based task queue for reliability and scalability
    - Proper error handling and status tracking
    - Dynamic imports to prevent dependency loading issues
    - Comprehensive logging and monitoring

Task Architecture:
    Tasks are designed to be executed by separate worker processes that can
    scale independently from the main web application. This allows for:
    - High-throughput security analysis
    - Resource isolation for ML model operations
    - Fault tolerance and recovery
    - Horizontal scaling of analysis capabilities

Background Processing Benefits:
    - Non-blocking web interface for immediate user feedback
    - Resource-intensive analysis without impacting web performance
    - Batch processing capabilities for large-scale assessments
    - Queue management for peak load handling

Task Queue Features:
    - Redis broker for reliable message delivery
    - Automatic retry mechanisms for failed tasks
    - Dead letter queues for error analysis
    - Task result persistence and monitoring

Example:
    Trigger background forensic analysis:
    
    >>> from app.tasks import run_forensic_analysis
    >>> # Queue forensic analysis for runtime log ID 123
    >>> run_forensic_analysis.send(123)

Dependencies:
    - Dramatiq: Distributed task processing framework
    - Redis: Message broker and result backend
    - Flask app context: Database and model access
    - Garak analyzer: Forensic analysis capabilities

Notes:
    - Dynamic imports prevent circular dependencies and ML model loading issues
    - Tasks operate with proper Flask application context
    - Comprehensive error handling ensures system stability
    - Status tracking enables monitoring and debugging
"""

# app/tasks.py
import dramatiq

# DO NOT import 'app' or 'db_session' at the top level here.
# This prevents the chain reaction of model loading.

@dramatiq.actor(queue_name="gpu", max_retries=3, time_limit=300000)
def run_forensic_analysis(log_id: int):
    """Execute comprehensive forensic analysis as a background task.
    
    Performs deep security analysis of user prompts and AI responses using
    the full Garak analysis suite. This task is designed to run asynchronously
    to avoid blocking the main web application during intensive analysis.
    
    Args:
        log_id (int): Database ID of the RuntimeLog entry to analyze
        
    Processing Workflow:
        1. Load RuntimeLog entry from database
        2. Update status to "RUNNING" for progress tracking
        3. Initialize Garak forensic analyzer with full detector suite
        4. Perform comprehensive threat analysis on prompt/response pair
        5. Store detailed risk profile in database
        6. Update status to "COMPLETE" or "ERROR" based on outcome
        
    Risk Profile Generation:
        The forensic analysis produces a comprehensive risk assessment including:
        - Individual detector scores for 30+ security threats
        - Confidence levels and threat categorization
        - Detailed vulnerability analysis and recommendations
        - Historical trend analysis and behavioral patterns
        
    Error Handling:
        - Graceful handling of analysis failures
        - Proper status updates for monitoring
        - Database transaction management
        - Comprehensive error logging for debugging
        
    Performance Considerations:
        - Designed for separate worker process execution
        - Resource isolation from main web application
        - Optimized for batch processing scenarios
        - Memory-efficient analysis pipeline
        
    Database Operations:
        - Atomic updates with proper transaction management
        - Status tracking throughout analysis lifecycle
        - Result persistence with comprehensive metadata
        - Session cleanup to prevent connection leaks
        
    Dynamic Imports:
        Uses dynamic imports to prevent circular dependencies and avoid
        loading heavy ML models in the main application process. This
        ensures clean separation between web and analysis components.
        
    Side Effects:
        - Updates RuntimeLog.forensic_status field
        - Stores comprehensive risk profile in forensic_risk_profile field
        - Logs analysis progress and results to console
        
    Example:
        >>> # Queue forensic analysis for runtime log
        >>> run_forensic_analysis.send(log_id=123)
        >>> # Task executes asynchronously in worker process
        
    Task States:
        - PENDING: Task queued but not yet started
        - RUNNING: Analysis in progress
        - COMPLETE: Analysis finished successfully
        - ERROR: Analysis failed with error
        
    Notes:
        - Requires separate Dramatiq worker process
        - Uses Redis broker for reliable task delivery
        - Proper Flask application context management
        - Thread-safe database operations
    """
    # --- DYNAMIC IMPORTS INSIDE THE TASK ---
    print(f"🔬 Background task started for RuntimeLog ID: {log_id}")
    from . import app, db_session
    from .models import RuntimeLog
    from .scanner.garak_loader import get_analyzer

    session = None  # Initialize session to None
    try:
        with app.app_context():
            session = db_session()
            log_entry = session.query(RuntimeLog).filter_by(id=log_id).one_or_none()

            if not log_entry:
                print(f"❌ Could not find RuntimeLog ID: {log_id}. Task will not be retried.")
                # This is a "clean" failure, no need to retry.
                return

            # Proceed with analysis
            log_entry.forensic_status = "RUNNING"
            session.commit()

            forensic_analyzer = get_analyzer()
            full_risk_profile = forensic_analyzer.analyze(
                log_entry.user_prompt, log_entry.llm_response
            )

            log_entry.forensic_risk_profile = full_risk_profile
            log_entry.forensic_status = "COMPLETE"
            print(f"✅ Forensic analysis complete for RuntimeLog ID: {log_id}")

    except Exception as e:
        print(f"❌ Error during forensic analysis for log {log_id}: {e}")
        # If an error occurs, try to update the log entry's status to "ERROR"
        if session and 'log_entry' in locals() and log_entry:
            log_entry.forensic_status = "ERROR"
            session.commit()
        # Re-raise the exception to trigger Dramatiq's retry mechanism.
        # After max_retries, the message will be discarded.
        raise

    finally:
        # Always ensure the session is closed.
        if session:
            session.close()
            
@dramatiq.actor(queue_name="gpu", max_retries=1, time_limit=3600000)
def execute_full_scan(run_id, scan_name, api_endpoint, api_key, api_model_identifier):
    """
    Dramatiq task to run the entire hybrid security scan in the background.
    """
    # --- THIS IS THE FIX ---
    # Import the scanner engine *inside* the task function.
    # This breaks the circular import at startup.
    from .scanner.engine import run_scan
    # --- END OF FIX ---

    print(f"BACKGROUND WORKER: Starting scan for run_id: {run_id}")
    try:
        run_scan(run_id, scan_name, api_endpoint, api_key, api_model_identifier)
        print(f"BACKGROUND WORKER: Scan for run_id {run_id} completed successfully.")
    except Exception as e:
        print(f"BACKGROUND WORKER: A critical error occurred during scan for run_id {run_id}: {e}")
        raise