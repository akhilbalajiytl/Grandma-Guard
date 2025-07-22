# app/tasks.py
import dramatiq
from dramatiq.brokers.redis import RedisBroker

# DO NOT import 'app' or 'db_session' at the top level here.
# This prevents the chain reaction of model loading.

# Configure the broker
redis_broker = RedisBroker(host="redis")
dramatiq.set_broker(redis_broker)

@dramatiq.actor
def run_forensic_analysis(log_id: int):
    """
    This is the background job that runs the full, slow Garak analysis.
    """
    # --- DYNAMIC IMPORTS INSIDE THE TASK ---
    # Import what we need only when the task is actually running.
    print(f"🔬 Background task started for RuntimeLog ID: {log_id}")
    from . import app, db_session
    from .models import RuntimeLog
    from .scanner.garak_loader import get_analyzer # This will use models loaded by another process

    with app.app_context():
        session = db_session()
        log_entry = session.query(RuntimeLog).filter_by(id=log_id).one_or_none()

        if not log_entry:
            print(f"❌ Could not find RuntimeLog ID: {log_id}")
            return
            
        try:
            # Note: This task now depends on the models being loaded
            # by the main webapp process. This is a more advanced
            # architecture. For now, let's assume the worker
            # might need to load them itself if run standalone.
            # A better long-term solution might be a dedicated ML service.
            
            # For now, let's just re-implement the old logic safely here.
            from .scanner.forensic_orchestrator import get_forensic_orchestrator # Assuming you still have this logic
            
            log_entry.forensic_status = "RUNNING"
            session.commit()
            
            forensic_orchestrator = get_forensic_orchestrator()
            full_risk_profile = forensic_orchestrator.analyze(
                log_entry.user_prompt, log_entry.llm_response
            )

            log_entry.forensic_risk_profile = full_risk_profile
            log_entry.forensic_status = "COMPLETE"
            print(f"✅ Forensic analysis complete for RuntimeLog ID: {log_id}")
            
        except Exception as e:
            log_entry.forensic_status = "ERROR"
            print(f"❌ Error during forensic analysis for log {log_id}: {e}")
        finally:
            session.commit()
            session.close()