# app/scanner/runtime_scanner.py
from .. import app, db_session
from ..models import RuntimeLog
from .api_utils import call_llm_api
from .engine import get_garak_detector_config, run_garak_evaluation_locally
from .evaluators import Evaluator

# This can be configured via environment variables in a real system
BLOCKED_RESPONSE_MESSAGE = "I'm sorry, but I cannot fulfill that request."


async def scan_and_respond_in_realtime(prompt: str, model_config: dict):
    """
    This is the core function for the LLM Firewall.
    It takes a prompt, gets a response, scans it, logs it, and decides what to return.
    """
    # 1. Call the actual LLM to get a response
    response = call_llm_api(
        model_config["api_endpoint"],
        model_config["api_key"],
        prompt,
        model_config["model_identifier"],
    )

    # 2. Evaluate the response in real-time
    evaluator = Evaluator()
    # For a simple firewall, we can just use the 'default' refusal detector
    # A more advanced version could parse the prompt for keywords to pick a detector
    detector_to_run = get_garak_detector_config("default")

    garak_status = run_garak_evaluation_locally(detector_to_run, prompt, response)
    judge_status = evaluator._run_judge_check(prompt, response)

    # 3. Make a decision
    decision = "ALLOWED"
    final_response = response

    # If any checker flags the response, block it.
    if garak_status == "FAIL" or judge_status == "FAIL":
        decision = "BLOCKED"
        final_response = BLOCKED_RESPONSE_MESSAGE
        print(
            f"🚨 RUNTIME BLOCK: Prompt triggered a {garak_status}/{judge_status} status."
        )

    # 4. Log the event to the database
    # We use app_context to ensure the database session works correctly in this async context
    with app.app_context():
        log_entry = RuntimeLog(
            user_prompt=prompt,
            llm_response=response,  # Log the original response, even if blocked
            garak_status=garak_status,
            judge_status=judge_status,
            decision=decision,
            model_identifier=model_config["model_identifier"],
        )
        session = db_session()
        try:
            session.add(log_entry)
            session.commit()
        except Exception as e:
            print(f"❌ Runtime Log DB Error: {e}")
            session.rollback()
        finally:
            session.close()

    # 5. Return the final response (either the real one or the blocked message)
    return final_response
