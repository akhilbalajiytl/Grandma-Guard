from .. import app, db_session
from ..models import RuntimeLog
from .api_utils import call_llm_api

# Import the GETTER function, not the class or an instance
from .garak_loader import get_analyzer
from .post_policy import PostGenerationPolicyEngine
from .triage_classifier import TriageClassifier

BLOCKED_RESPONSE_MESSAGE = (
    "I'm sorry, but I cannot fulfill that request due to security policies."
)


async def scan_and_respond_in_realtime(prompt: str, model_config: dict):
    forensic_analyzer = get_analyzer()
    triage_decision, triage_reason = TriageClassifier.classify(prompt)

    final_response = ""
    llm_response_for_log = ""
    risk_profile = {
        "triage": {"decision": triage_decision, "reason": triage_reason},
        "scores": {},  # This will hold the numeric Garak scores
    }
    final_decision = ""

    if triage_decision == "BLOCK":
        final_response = BLOCKED_RESPONSE_MESSAGE
        llm_response_for_log = "BLOCKED-BY-TRIAGE"
        final_decision = "BLOCKED"

    elif triage_decision == "ALLOW":
        # If triage allows it, we trust it for speed. Get the response and return it.
        # No deep scan is performed for these clearly benign prompts.
        final_response = call_llm_api(
            model_config["api_endpoint"],
            model_config["api_key"],
            prompt,
            model_config["model_identifier"],
        )
        llm_response_for_log = final_response
        final_decision = "ALLOWED"
        risk_profile["triage"]["deep_scan_status"] = "SKIPPED_BENIGN"

    elif triage_decision == "DEEP_SCAN":
        # --- STAGE 2: GET LLM RESPONSE & PERFORM DEEP SCAN ---
        # First, get the model's response
        llm_response = call_llm_api(
            model_config["api_endpoint"],
            model_config["api_key"],
            prompt,
            model_config["model_identifier"],
        )
        llm_response_for_log = llm_response
        final_response = (
            llm_response  # For now, we return the response and log forensics
        )

        # Now, run the deep forensic analysis on the (prompt, response) pair
        print(
            f"🔬 Performing deep forensic analysis for prompt flagged as '{triage_reason}'..."
        )
        deep_scan_results = forensic_analyzer.analyze(prompt, llm_response)
        # Put the scores in the 'scores' sub-dictionary
        risk_profile["scores"] = deep_scan_results

        # Now, make a final decision based on the analysis of the response.
        post_gen_decision, post_gen_reason = PostGenerationPolicyEngine(risk_profile)

        if post_gen_decision == "BLOCK":
            final_response = BLOCKED_RESPONSE_MESSAGE
            final_decision = "BLOCKED"
            # Add the reason to the risk profile for logging
            risk_profile["post_gen_reason"] = post_gen_reason
        else:
            final_response = llm_response
            final_decision = "ALLOWED_WITH_FINDINGS"

    # Log the event to the database
    with app.app_context():
        log_entry = RuntimeLog(
            user_prompt=prompt,
            llm_response=llm_response_for_log,
            # The JSON column is now named forensic_risk_profile, let's use that.
            # We will store the entire new risk_profile structure.
            # Let's remove triage_risk_profile for simplicity.
            forensic_risk_profile=risk_profile,
            decision=final_decision,
            model_identifier=model_config["model_identifier"],
            forensic_status="COMPLETE",
        )
        session = db_session()
        session.add(log_entry)
        session.commit()
        session.close()

    # Return the final response to the user
    return final_response
