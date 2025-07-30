"""
GrandmaGuard Post-Generation Policy Engine Module

This module implements the post-generation security policy evaluation system
for GrandmaGuard. After an AI model generates a response, this engine analyzes
the output using multiple detection methods to identify potentially harmful
content that should be blocked before reaching the user.

Core Functionality:
- Multi-layered post-generation content analysis
- Context-aware policy enforcement based on input classification
- Specialized detection for code injection, toxicity, and refusal bypasses
- Threshold-based blocking with detailed reasoning

The post-generation engine serves as a critical safety net, catching harmful
outputs that may have bypassed input-level filtering or resulted from subtle
prompt manipulation techniques.

Key Detection Categories:
- Code Injection: XSS, SQL injection, malicious code generation
- Toxicity & Harmful Content: Slurs, toxic comments, harmful instructions
- Security Bypasses: Refusal mechanism circumvention
- Data Leakage: PII exposure, credential generation

Functions:
    PostGenerationPolicyEngine: Main post-generation analysis and decision engine

Author: GrandmaGuard Security Team
License: MIT
"""

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
) -> tuple[str, str]:
    """
    Analyze post-generation content and make security policy decisions.
    
    This function implements a two-tier post-generation security policy that
    evaluates AI model outputs using multiple detection methods. It combines
    input context (from LlamaGuard pre-screening) with output analysis (from
    Garak detectors) to make nuanced blocking decisions.
    
    Policy Rules:
    1. Unconditional Blocking: Block outputs containing harmful content
       regardless of input intent (toxicity, code injection, etc.)
    2. Context-Aware Blocking: Block compliant responses to unsafe prompts
       (successful jailbreak/refusal bypass detection)
    
    The engine uses different thresholds for different threat types,
    balancing security effectiveness with false positive minimization.
    
    Args:
        llama_guard_input_verdict (dict): Input classification results from LlamaGuard.
                                        Expected to contain 'status' field with
                                        'SAFE' or 'UNSAFE' classification.
        garak_risk_profile (dict): Output analysis results from Garak detectors.
                                 Expected to contain 'scores' dict mapping
                                 detector names to normalized risk scores.
    
    Returns:
        tuple[str, str]: A tuple containing:
            - Decision: "ALLOW" or "BLOCK"
            - Reason: Detailed explanation of the decision
    
    Example:
        >>> input_verdict = {"status": "UNSAFE", "categories": ["violence"]}
        >>> risk_profile = {"scores": {"refusal_v2": 0.98, "toxicity": 0.3}}
        >>> decision, reason = PostGenerationPolicyEngine(input_verdict, risk_profile)
        >>> print(f"{decision}: {reason}")
        BLOCK: Post-Gen Block: Model complied with an unsafe prompt...
        
        >>> safe_input = {"status": "SAFE"}
        >>> low_risk = {"scores": {"toxicity": 0.2, "xss_markdown_basic": 0.1}}
        >>> decision, reason = PostGenerationPolicyEngine(safe_input, low_risk)
        >>> print(f"{decision}: {reason}")
        ALLOW: All post-generation checks passed.
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
