# app/scanner/runtime_scanner.py (Final Corrected Version)

from .. import app, db_session
from ..models import RuntimeLog
from .api_utils import call_llm_api
from .post_policy import PostGenerationPolicyEngine
from .garak_loader import get_analyzer
from .llama_guard import LlamaGuardEvaluator
from .smart_classifier import SmartClassifier 

BLOCKED_RESPONSE_MESSAGE = (
    "I'm sorry, but this request has been blocked as it violates our safety policies."
)

# This is correct. We create one instance of our lightweight API clients.
smart_classifier = SmartClassifier()
llama_guard = LlamaGuardEvaluator()

async def scan_and_respond_in_realtime(prompt: str, model_config: dict):
    # Get the shared, pre-loaded Garak analyzer instance.
    forensic_analyzer = get_analyzer()
    # We will use the 'smart_classifier' instance we already created above.

    # Initialize variables
    final_response = ""
    llm_response_for_log = ""
    risk_profile = {}
    final_decision = ""

    # --- STAGE 1: SMART TRIAGE CLASSIFICATION ---
    print("  - Running Smart Triage Classifier...")
    # This line is now correct, it uses the instance from the top of the file.
    triage_decision, triage_reason = smart_classifier.classify(prompt)
    print(f"  - Smart Triage Result: {triage_decision}")
    risk_profile["smart_triage"] = {
        "decision": triage_decision,
        "reason": triage_reason,
        "model": "grandma-guard-classifier"
    }

    if triage_decision == "BLOCK":
        print("🚨 Smart Triage BLOCK: Prompt flagged for immediate blocking.")
        final_response = BLOCKED_RESPONSE_MESSAGE
        llm_response_for_log = "BLOCKED-BY-SMART-CLASSIFIER"
        final_decision = "BLOCKED"
    else:
        # --- STAGE 2: LLAMA GUARD INPUT ANALYSIS ---
        print("  - Running Llama Guard input scan...")
        llama_guard_verdict = llama_guard.evaluate_prompt(prompt)
        print(f"  - Llama Guard Input Result: {llama_guard_verdict}")
        risk_profile["llama_guard_input_scan"] = llama_guard_verdict

        if llama_guard_verdict.get("status") == "UNSAFE":
            print(f"🚨 Llama Guard BLOCK: Prompt flagged as {llama_guard_verdict.get('category_name')}.")
            final_response = BLOCKED_RESPONSE_MESSAGE
            llm_response_for_log = "BLOCKED-BY-LLAMA-GUARD-INPUT-SCAN"
            final_decision = "BLOCKED"
        else:
            # --- STAGE 3: QUERY TARGET LLM & GARAK OUTPUT ANALYSIS ---
            print("  - All input scans passed. Querying target LLM...")
            # Note: call_llm_api is not async in your provided file, if it is, you need 'await'
            llm_response = call_llm_api(
                model_config["api_endpoint"],
                model_config["api_key"],
                prompt,
                model_config["model_identifier"],
            )
            llm_response_for_log = llm_response

            print("🔬 Performing Garak forensic analysis on LLM response...")
            garak_scores = forensic_analyzer.analyze(prompt, llm_response)
            risk_profile["garak_output_scan"] = garak_scores

            post_gen_decision, post_gen_reason = PostGenerationPolicyEngine(
                llama_guard_input_verdict=llama_guard_verdict,
                garak_risk_profile={"scores": garak_scores},
            )

            if post_gen_decision == "BLOCK":
                final_response = BLOCKED_RESPONSE_MESSAGE
                final_decision = "BLOCKED"
                risk_profile["post_gen_reason"] = post_gen_reason
            else:
                final_response = llm_response
                final_decision = "ALLOWED"

    # --- LOGGING ---
    with app.app_context():
        log_entry = RuntimeLog(
            user_prompt=prompt,
            llm_response=llm_response_for_log,
            forensic_risk_profile=risk_profile,
            decision=final_decision,
            model_identifier=model_config["model_identifier"],
            forensic_status="COMPLETE",
        )
        session = db_session()
        session.add(log_entry)
        session.commit()
        session.close()

    return final_response