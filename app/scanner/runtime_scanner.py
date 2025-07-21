from .. import app, db_session
from ..models import RuntimeLog
from .api_utils import call_llm_api

# Import the GETTER function, not the class or an instance
from .garak_loader import get_analyzer
from .llama_guard import LlamaGuardEvaluator
from .post_policy import PostGenerationPolicyEngine

BLOCKED_RESPONSE_MESSAGE = (
    "I'm sorry, but I cannot fulfill that request due to security policies."
)

llama_guard = LlamaGuardEvaluator()


async def scan_and_respond_in_realtime(prompt: str, model_config: dict):
    forensic_analyzer = get_analyzer()

    final_response = ""
    llm_response_for_log = ""
    # The risk profile will now be simpler at the start
    risk_profile = {}
    final_decision = ""

    # --- STAGE 1: LLAMA GUARD INPUT ANALYSIS (RUNS ON EVERY PROMPT) ---
    print("  - Running Llama Guard input scan...")
    llama_guard_verdict = llama_guard.evaluate_prompt(prompt)
    print(f"  - Llama Guard Input Result: {llama_guard_verdict}")
    risk_profile["llama_guard_input_scan"] = llama_guard_verdict

    if llama_guard_verdict.get("status") == "UNSAFE":
        print(
            f"🚨 Llama Guard BLOCK: Prompt flagged as {llama_guard_verdict.get('category_name')}."
        )
        final_response = BLOCKED_RESPONSE_MESSAGE
        llm_response_for_log = "BLOCKED-BY-LLAMA-GUARD-INPUT-SCAN"
        final_decision = "BLOCKED"
    else:
        # --- PROMPT IS SAFE, PROCEED TO TARGET LLM ---
        print("  - Llama Guard deemed prompt safe. Querying target LLM...")
        llm_response = call_llm_api(
            model_config["api_endpoint"],
            model_config["api_key"],
            prompt,
            model_config["model_identifier"],
        )
        llm_response_for_log = llm_response

        # --- STAGE 2: GARAK OUTPUT ANALYSIS ---
        print("🔬 Performing Garak forensic analysis on LLM response...")
        garak_scores = forensic_analyzer.analyze(prompt, llm_response)
        risk_profile["garak_output_scan"] = garak_scores

        # Run the Post-Generation Policy Engine on the Garak results
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
