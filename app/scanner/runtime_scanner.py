# app/scanner/runtime_scanner.py
from .. import app, db_session
from ..models import RuntimeLog
from ..tasks import run_forensic_analysis
from .api_utils import call_llm_api
from .policy_engine import PolicyEngine
from .triage_orchestrator import get_triage_orchestrator

BLOCKED_RESPONSE_MESSAGE = "I'm sorry, but I cannot fulfill that request."


async def scan_and_respond_in_realtime(prompt: str, model_config: dict):
    # 1. Call the LLM
    response = call_llm_api(
        model_config["api_endpoint"],
        model_config["api_key"],
        prompt,
        model_config["model_identifier"],
    )

    # Get the orchestrator instance and then analyze
    triage_orchestrator = get_triage_orchestrator()
    triage_profile = triage_orchestrator.analyze(prompt, response)

    # 3. Make a real-time decision
    decision = PolicyEngine.decide(prompt, triage_profile)  # Pass the prompt in
    final_response = response if decision == "ALLOWED" else BLOCKED_RESPONSE_MESSAGE

    # 4. Log the initial event to the DB
    with app.app_context():
        log_entry = RuntimeLog(
            user_prompt=prompt,
            llm_response=response,
            triage_risk_profile=triage_profile,
            decision=decision,
            model_identifier=model_config["model_identifier"],
            forensic_status="PENDING",
        )
        session = db_session()
        session.add(log_entry)
        session.commit()
        log_id = log_entry.id
        session.close()

    # 5. Kick off the slow forensic analysis in the background
    run_forensic_analysis.send(log_id)

    # 6. Return the response to the user immediately
    return final_response
