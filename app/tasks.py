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
from dramatiq.brokers.redis import RedisBroker

# A 24-hour time limit in milliseconds. This is effectively infinite for our purposes.
TWENTY_FOUR_HOURS = 24 * 60 * 60 * 1000 

# Configure the broker
redis_broker = RedisBroker(host="redis")
dramatiq.set_broker(redis_broker)

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
    # Import what we need only when the task is actually running.
    # By this time, the web app and db will be fully initialized.
    print(f"🔬 Background task started for RuntimeLog ID: {log_id}")
    from . import app, db_session
    from .models import RuntimeLog
    from .scanner.garak_loader import get_analyzer

    with app.app_context():
        session = db_session()
        try:
            log_entry = session.query(RuntimeLog).filter_by(id=log_id).one_or_none()
            if not log_entry:
                print(f"❌ Could not find RuntimeLog ID: {log_id}")
                return

            log_entry.forensic_status = "RUNNING"
            session.commit()

            # Get the pre-loaded analyzer instance
            forensic_analyzer = get_analyzer()
            full_risk_profile = forensic_analyzer.analyze(
                log_entry.user_prompt, log_entry.llm_response
            )

            log_entry.forensic_risk_profile = full_risk_profile
            log_entry.forensic_status = "COMPLETE"
            print(f"✅ Forensic analysis complete for RuntimeLog ID: {log_id}")

        except Exception as e:
            # It's good practice to try and update the status to ERROR
            if 'log_entry' in locals() and log_entry:
                log_entry.forensic_status = "ERROR"
            print(f"❌ Error during forensic analysis for log {log_id}: {e}")
        finally:
            session.commit()
            session.close()


@dramatiq.actor(queue_name="gpu", max_retries=1, time_limit=TWENTY_FOUR_HOURS) # 2-hour time limit for full scans
def execute_scan_with_mode(run_id, api_config, scan_mode, llama_guard_soft_block=False):
    """
    Executes a security scan based on the selected mode.
    Handles 'payloads_only', 'garak_only', and 'both'.
    """
    # --- DYNAMIC IMPORTS INSIDE THE TASK ---
    from . import app, db_session
    from .models import TestRun
    from .scanner.engine import run_scan as run_payload_scan
    from .scanner.garak_cli_runner import GarakCLIRunner, convert_garak_results_to_test_results
    
    print(f"BACKGROUND WORKER: Starting scan for run_id: {run_id}, mode: {scan_mode}")
    
    with app.app_context():
        session = db_session()
        try:
            test_run = session.query(TestRun).filter_by(id=run_id).first()
            if not test_run:
                print(f"❌ WORKER: Could not find TestRun with ID {run_id}. Aborting task.")
                return

            # --- Mode 1: Payloads Scan ---
            if scan_mode in ["payloads_only", "both"]:
                print(f"  -> WORKER: Running payload-based tests for run {run_id}...")
                run_payload_scan(
                    run_id,
                    test_run.scan_name,
                    api_config["endpoint"],
                    api_config["key"],
                    api_config["model_id"],
                    llama_guard_soft_block
                )
                print(f"  -> WORKER: Payload-based tests completed for run {run_id}.")

            # --- Mode 2: Garak CLI Scan (Corrected) ---
            if scan_mode in ["garak_only", "both"]:
                print(f"  -> WORKER: Running Garak CLI scan for run {run_id}...")
                garak_runner = GarakCLIRunner()
                try:
                    # --- THIS IS THE FIX ---
                    # The function now returns only the list of probe summaries.
                    probe_summaries = garak_runner.run_garak_scan(api_config)

                    if probe_summaries:
                        print(f"  -> WORKER: Garak scan successful. Converting {len(probe_summaries)} probe summaries to database format...")
                        garak_test_results = convert_garak_results_to_test_results(probe_summaries, run_id)
                        session.add_all(garak_test_results)
                        session.commit()
                        print(f"  -> WORKER: Saved {len(garak_test_results)} Garak results to the database.")
                    else:
                        print(f"  -> WORKER: Garak scan failed or produced no results.")
                    # --- END OF FIX ---
                finally:
                    # The cleanup call was inside the Garak runner, which is correct.
                    # No need to call it here.
                    pass

            # --- Finalize the TestRun ---
            # Recalculate the final score based on ALL results now in the DB
            test_run_to_update = session.query(TestRun).get(run_id)
            if test_run_to_update and test_run_to_update.results:
                all_results = test_run_to_update.results
                passed_count = sum(1 for r in all_results if r.status == "PASS")
                test_run_to_update.overall_score = passed_count / len(all_results)
            
            session.commit()
            print(f"✅ WORKER: Scan for run_id {run_id} (mode: {scan_mode}) is fully complete.")

        except Exception as e:
            print(f"❌ WORKER: A critical error occurred in execute_scan_with_mode for run_id {run_id}: {e}")
            import traceback
            traceback.print_exc()
            session.rollback()
            # Optionally, update the test run to an ERROR state
        finally:
            session.close()

@dramatiq.actor(queue_name="gpu", max_retries=0, time_limit=TWENTY_FOUR_HOURS)
def execute_ad_hoc_test(run_id, test_case_data, api_config, llama_guard_soft_block=False):
    """
    Dramatiq task to run a single, ad-hoc test case provided directly.
    """
    # --- DYNAMIC IMPORTS ---
    import asyncio
    import aiohttp
    from . import app, db_session
    from .models import TestRun
    from .scanner.engine import process_redteam_case, process_technical_case
    from .scanner.llm_assessor import LLMAssessor
    from .scanner.llama_guard import LlamaGuardEvaluator
    from .scanner.garak_loader import get_analyzer

    print(f"BACKGROUND WORKER: Starting ad-hoc test for run_id: {run_id}")

    with app.app_context():
        session = db_session()
        try:
            tools = {
                "assessor": LLMAssessor(),
                "llama_guard": LlamaGuardEvaluator(),
                "forensic_analyzer": get_analyzer()
            }

            async def run():
                async with aiohttp.ClientSession() as http_session:
                    # Dispatch to the correct processor based on the test case structure
                    if "undesirable_outcome" in test_case_data:
                        await process_redteam_case(http_session, session, tools, run_id, test_case_data, api_config)
                    else:
                        await process_technical_case(http_session, session, tools, run_id, test_case_data, api_config, llama_guard_soft_block)
            
            asyncio.run(run())

            # Finalize the run score
            test_run_to_update = session.query(TestRun).get(run_id)
            if test_run_to_update and test_run_to_update.results:
                all_results = test_run_to_update.results
                passed_count = sum(1 for r in all_results if r.status == "PASS")
                test_run_to_update.overall_score = passed_count / len(all_results)
            
            session.commit()
            print(f"✅ WORKER: Ad-hoc test for run_id {run_id} is complete.")

        except Exception as e:
            print(f"❌ WORKER: A critical error occurred in ad-hoc test for run_id {run_id}: {e}")
            import traceback
            traceback.print_exc()
            session.rollback()
        finally:
            session.close()