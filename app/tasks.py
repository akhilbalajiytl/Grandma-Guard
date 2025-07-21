# app/tasks.py
import dramatiq
from dramatiq.brokers.redis import RedisBroker

from . import app, db_session
from .models import RuntimeLog

# --- DO NOT IMPORT the orchestrator at the top level ---
# from .scanner.forensic_orchestrator import forensic_orchestrator

# Configure the broker to connect to our Redis service
redis_broker = RedisBroker(host="redis")
dramatiq.set_broker(redis_broker)


@dramatiq.actor
def run_forensic_analysis(log_id: int):
    """
    This is the background job that runs the full, slow Garak analysis.
    """
    # Import the orchestrator *inside* the function, only when it's needed.
    # This breaks the circular import at startup.
    from .scanner.forensic_orchestrator import get_forensic_orchestrator

    print(f"🔬 Starting forensic analysis for RuntimeLog ID: {log_id}")
    with app.app_context():
        session = db_session()
        log_entry = session.query(RuntimeLog).filter_by(id=log_id).one_or_none()

        if not log_entry:
            print(f"❌ Could not find RuntimeLog ID: {log_id}")
            return

        try:
            log_entry.forensic_status = "RUNNING"
            session.commit()

            # Get the orchestrator instance and then analyze
            forensic_orchestrator = get_forensic_orchestrator()
            full_risk_profile = forensic_orchestrator.analyze(
                log_entry.user_prompt, log_entry.llm_response
            )

            # Update the record with the results
            log_entry.forensic_risk_profile = full_risk_profile
            log_entry.forensic_status = "COMPLETE"
            print(f"✅ Forensic analysis complete for RuntimeLog ID: {log_id}")

        except Exception as e:
            log_entry.forensic_status = "ERROR"
            print(f"❌ Error during forensic analysis for log {log_id}: {e}")

        finally:
            session.commit()
            session.close()
