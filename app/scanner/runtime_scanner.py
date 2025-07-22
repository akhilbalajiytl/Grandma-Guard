# app/scanner/runtime_scanner.py
from .. import app, db_session
from ..models import RuntimeLog
from .api_utils import call_llm_api
from .post_policy import PostGenerationPolicyEngine
# Import the GETTERS for both the analyzer and the new classifier
from .garak_loader import get_analyzer, get_classifier
from .llama_guard import LlamaGuardEvaluator

BLOCKED_RESPONSE_MESSAGE = (
    "I'm sorry, but this request has been blocked as it violates our safety policies."
)

# Instantiate Llama Guard once, as it's lightweight (just holds a key).
llama_guard = LlamaGuardEvaluator()

async def scan_and_respond_in_realtime(prompt: str, model_config: dict):
    # Get the shared, pre-loaded instances at the start of the request.
    forensic_analyzer = get_analyzer()
    smart_classifier = get_classifier()

    # Initialize variables
    final_response = ""
    llm_response_for_log = ""
    risk_profile = {}
    final_decision = ""

    # --- STAGE 1: SMART TRIAGE CLASSIFICATION ---
    # This is our fast, fine-tuned first line of defense.
    print("  - Running Smart Triage Classifier...")
    triage_decision, triage_reason = smart_classifier.classify(prompt)
    print(f"  - Smart Triage Result: {triage_decision}")
    risk_profile["smart_triage"] = {
        "decision": triage_decision,
        "reason": triage_reason,
        "model": "grandma-guard-phi3-classifier"
    }

    # If the SmartClassifier is highly confident the prompt is malicious, we block immediately.
    if triage_decision == "BLOCK":
        print("🚨 Smart Triage BLOCK: Prompt flagged for immediate blocking.")
        final_response = BLOCKED_RESPONSE_MESSAGE
        llm_response_for_log = "BLOCKED-BY-SMART-CLASSIFIER"
        final_decision = "BLOCKED"
    else:
        # If the prompt is classified as ALLOW or DEEP_SCAN, it proceeds to the next layer.
        # This creates a "zero-trust" funnel where prompts must pass multiple checks.
        
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

            # Run the Post-Generation Policy Engine on the Garak results and Llama Guard context
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
                # We can now confidently say it's ALLOWED after passing all checks
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