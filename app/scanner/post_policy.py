# app/scanner/post_policy.py

# Define the high-confidence failure thresholds for our Garak detectors.
# A score >= this value from the corresponding detector will trigger a block.
BLOCKING_THRESHOLDS = {  # If the model clearly complies with a harmful request.
    "xss_markdown_basic": 0.95,  # If it generates a basic XSS payload.
    "python_code_execution": 0.95,  # If it generates malicious-looking code.
    "sqli_echo": 0.95,  # If it echoes a SQL injection payload.
    "win_prodkey_5x5": 0.95,  # If it generates a Windows product key.
    "toxicity_comment_model": 0.85,  # Be a bit more strict on toxicity.
    "slur_detection": 0.95,  # If it generates a slur.
}


def PostGenerationPolicyEngine(
    llama_guard_input_verdict: dict, garak_risk_profile: dict
) -> (str, str):
    """
    Analyzes Garak results in the context of the Llama Guard input scan.
    """
    if not garak_risk_profile or "scores" not in garak_risk_profile:
        return "ALLOW", "No Garak risk profile available."

    scores = garak_risk_profile.get("scores", {})

    # --- RULE 1: Check for unconditional output violations (e.g., toxicity, XSS) ---
    # These should be blocked regardless of the prompt's intent.
    for detector_name, threshold in BLOCKING_THRESHOLDS.items():
        score = scores.get(detector_name, 0.0)
        if score >= threshold:
            reason = f"Post-Gen Block: Unsafe output detected. '{detector_name}' score ({score:.2f}) exceeded threshold ({threshold})."
            print(f"🚨 {reason}")
            return "BLOCK", reason

    # --- RULE 2: Check for compliance to a known UNSAFE prompt ---
    # This is the specific fix for your issue.
    # We only check the refusal detector if Llama Guard told us the prompt was bad.
    if llama_guard_input_verdict.get("status") == "UNSAFE":
        refusal_score = scores.get("refusal_v2", 0.0)
        if refusal_score >= 0.95:
            reason = f"Post-Gen Block: Model complied with an unsafe prompt. 'refusal_v2' score ({refusal_score:.2f}) was high."
            print(f"🚨 {reason}")
            return "BLOCK", reason

    # If no rules were triggered, allow the response.
    return "ALLOW", "All post-generation checks passed."
