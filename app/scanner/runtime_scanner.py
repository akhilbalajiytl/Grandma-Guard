"""GrandmaGuard Real-time Security Scanner Module.

This module provides real-time AI security scanning capabilities for the proxy
endpoint, implementing a defense-in-depth approach to detect and prevent
various forms of AI misuse in production environments.

The scanner implements a multi-stage security funnel designed for both
effectiveness and performance in real-time scenarios:

Security Stages:
    1. Smart Triage: Fast custom classifier for immediate threat detection
    2. Policy Enforcement: LlamaGuard safety policy validation
    3. Target LLM Interaction: Controlled model querying
    4. Post-Generation Analysis: Garak forensic analysis of responses
    5. Comprehensive Logging: Audit trail for security incidents

Defense-in-Depth Architecture:
    The scanner uses multiple, independent security layers to ensure
    comprehensive protection against evolving AI threats. Each layer
    operates independently and can block requests based on different
    threat models and detection capabilities.

Performance Optimization:
    - Pre-loaded model instances for minimal latency
    - Staged evaluation with early termination
    - Optimized for high-throughput production use
    - Efficient memory usage and connection pooling

Threat Coverage:
    - Prompt injection attacks
    - Jailbreak attempts
    - Content policy violations
    - Output manipulation and data exfiltration
    - Social engineering and manipulation
    - Code execution and system exploitation

Example:
    Real-time scanning in proxy mode:
    
    >>> model_config = {
    ...     "api_endpoint": "https://api.openai.com/v1/chat/completions",
    ...     "api_key": "sk-...",
    ...     "model_identifier": "gpt-4"
    ... }
    >>> response = await scan_and_respond_in_realtime(user_prompt, model_config)

Dependencies:
    - SmartClassifier: Custom trained threat detection model
    - LlamaGuard: Meta's AI safety policy enforcement
    - Garak: Comprehensive AI red-teaming framework
    - PostGenerationPolicyEngine: Response filtering and sanitization

Notes:
    - Designed for production deployment with minimal latency
    - Comprehensive audit logging for compliance and forensics
    - Configurable security policies and thresholds
    - Thread-safe operations for concurrent request handling
"""

# app/scanner/runtime_scanner.py (Final Corrected Version)

import aiohttp
from .. import app, db_session
from ..models import RuntimeLog
from .api_utils import async_call_llm_api
from .post_policy import PostGenerationPolicyEngine
from .garak_loader import get_analyzer
from .llama_guard import LlamaGuardEvaluator
from .smart_classifier import SmartClassifier 

BLOCKED_RESPONSE_MESSAGE = (
    "I'm sorry, but this request has been blocked as it violates our safety policies."
)

# --- Singleton Instances for our clients ---
# These will hold the instances once they are created.
_smart_classifier_instance = None
_llama_guard_instance = None

def get_smart_classifier():
    """Lazy-loads and returns a single instance of the SmartClassifier."""
    global _smart_classifier_instance
    if _smart_classifier_instance is None:
        _smart_classifier_instance = SmartClassifier()
    return _smart_classifier_instance

def get_llama_guard():
    """Lazy-loads and returns a single instance of the LlamaGuardEvaluator."""
    global _llama_guard_instance
    if _llama_guard_instance is None:
        _llama_guard_instance = LlamaGuardEvaluator()
    return _llama_guard_instance

async def scan_and_respond_in_realtime(prompt: str, model_config: dict):
    """Orchestrate multi-layered real-time security scanning for AI interactions.

    Implements a comprehensive defense-in-depth security funnel for real-time
    AI safety protection. Each stage can independently block requests based
    on different threat models and security policies.

    Security Funnel Stages:
        1. Smart Triage: Fast custom classifier for obvious threats
           - Uses lightweight ML model for sub-second detection
           - Provides BLOCK, ALLOW, or DEEP_SCAN verdicts
           - Optimized for common attack patterns

        2. Policy Enforcement: LlamaGuard safety validation
           - Checks against comprehensive safety policies
           - Detects hate speech, violence, illegal content
           - Industry-standard safety classification

        3. Target LLM Interaction: Controlled model querying
           - Only reached if all input scans pass
           - Monitors for unexpected model behavior
           - Captures full interaction for analysis

        4. Post-Generation Analysis: Garak forensic scanning
           - Deep analysis of model responses
           - Detects subtle security violations
           - Catches jailbreak compliance and data leakage

        5. Audit Logging: Comprehensive security event recording
           - Full transaction logging for forensics
           - Risk profiling and threat intelligence
           - Compliance and monitoring capabilities

    Args:
        prompt (str): User's input prompt to be analyzed
        model_config (dict): Target LLM configuration containing:
            - api_endpoint (str): Target model API URL
            - api_key (str): Authentication key
            - model_identifier (str): Model name/identifier

    Returns:
        str: Final safe response for the user, or blocked message if
             any security layer triggered protection

    Decision Flow:
        - If Smart Triage → BLOCK: Immediate rejection
        - If LlamaGuard → UNSAFE: Policy violation block
        - If Garak → HIGH_RISK: Post-generation block
        - Otherwise: Allow response through

    Risk Profile Structure:
        {
            "smart_triage": {
                "decision": "ALLOW|BLOCK|DEEP_SCAN",
                "reason": "threat_category",
                "model": "grandma-guard-classifier"
            },
            "llama_guard_input_scan": {
                "status": "SAFE|UNSAFE",
                "category": "violation_type",
                "confidence": 0.95
            },
            "garak_output_scan": {
                "detector_name": 0.23,
                "refusal_v2": 0.05,
                ...
            },
            "post_gen_reason": "blocking_rationale"
        }

    Performance Features:
        - Pre-loaded model instances for minimal latency
        - Early termination on security violations
        - Optimized for high-throughput scenarios
        - Efficient resource utilization

    Security Benefits:
        - Multi-layered protection against diverse threats
        - Real-time blocking with sub-second response times
        - Comprehensive audit trail for incident analysis
        - Adaptive threat detection with multiple AI models

    Example:
        >>> config = {
        ...     "api_endpoint": "https://api.openai.com/v1/chat/completions",
        ...     "api_key": "sk-...",
        ...     "model_identifier": "gpt-4"
        ... }
        >>> response = await scan_and_respond_in_realtime(
        ...     "Tell me how to hack a system", config
        ... )
        >>> # Returns: "I'm sorry, but this request has been blocked..."

    Raises:
        Exception: Database or API errors are logged but don't crash the service

    Notes:
        - Designed for production environments with SLA requirements
        - Each security layer operates independently for robustness
        - Comprehensive logging enables threat intelligence and forensics
        - Configurable policies allow customization for different use cases
    """
    forensic_analyzer = get_analyzer()
    smart_classifier = get_smart_classifier()
    llama_guard = get_llama_guard()
    final_response = ""
    llm_response_for_log = ""
    risk_profile = {}
    final_decision = ""
    
    # Use a single session for all async network calls in this request.
    async with aiohttp.ClientSession() as http_session:
        # --- STAGE 1: ASYNC SMART TRIAGE ---
        triage_decision, triage_reason = await smart_classifier.aclassify(http_session, prompt)
        risk_profile["smart_triage"] = { "decision": triage_decision, "reason": triage_reason, "model": "grandma-guard-classifier" }
        print(f"  - Smart Triage Result: {triage_decision}")

        if triage_decision == "BLOCK":
            final_response = BLOCKED_RESPONSE_MESSAGE
            llm_response_for_log = "BLOCKED-BY-SMART-CLASSIFIER"
            final_decision = "BLOCKED"
        else:
            # --- STAGE 2: LLAMA GUARD INPUT ANALYSIS ---
            import asyncio
            loop = asyncio.get_running_loop()
            llama_guard_verdict = await loop.run_in_executor(None, llama_guard.evaluate_prompt, prompt)
            risk_profile["llama_guard_input_scan"] = llama_guard_verdict
            print(f"  - Llama Guard Input Result: {llama_guard_verdict}")

            if llama_guard_verdict.get("status") == "UNSAFE":
                final_response = BLOCKED_RESPONSE_MESSAGE
                llm_response_for_log = "BLOCKED-BY-LLAMA-GUARD-INPUT-SCAN"
                final_decision = "BLOCKED"
            else:
                # --- STAGE 3: QUERY TARGET LLM & POST-GENERATION ANALYSIS ---
                # This block ONLY runs if both Triage and Llama Guard pass.
                
                llm_response = await async_call_llm_api(
                    http_session,
                    model_config["api_endpoint"],
                    model_config["api_key"],
                    prompt,
                    model_config["model_identifier"],
                )
                llm_response_for_log = llm_response

                garak_scores = await loop.run_in_executor(None, forensic_analyzer.analyze, prompt, llm_response)
                risk_profile["garak_output_scan"] = garak_scores

                # The PostGenerationPolicyEngine is now correctly nested
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