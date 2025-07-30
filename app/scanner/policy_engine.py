"""
GrandmaGuard Policy Engine Module

This module implements the central policy decision engine for GrandmaGuard's
runtime security scanning system. The PolicyEngine class evaluates threat
detection results and makes blocking/allowing decisions based on configurable
risk thresholds.

Core Functionality:
- Risk threshold evaluation for multiple threat categories
- Binary decision making (ALLOWED/BLOCKED) based on detector scores
- Runtime threat blocking with detailed logging
- Default-allow security posture with selective blocking

The policy engine serves as the final decision point in the scanning pipeline,
translating numeric risk scores from various detectors into actionable security
decisions for production AI systems.

Classes:
    PolicyEngine: Central policy decision engine with threshold-based blocking

Security Categories:
    - DAN: Direct jailbreak attempts and prompt injection
    - AnyCode: Malicious code generation requests
    - StartsWith: PII leak and data exfiltration attempts

Author: GrandmaGuard Security Team
License: MIT
"""

# app/scanner/policy_engine.py


class PolicyEngine:
    """
    Central policy decision engine for GrandmaGuard security scanning.
    
    This class implements threshold-based security policy enforcement,
    evaluating threat detection results and making binary allow/block
    decisions for AI model interactions. The engine uses configurable
    risk thresholds to balance security effectiveness with usability.
    
    The policy engine follows a default-allow security posture, only
    blocking interactions when threat scores exceed predefined thresholds.
    This approach minimizes false positives while ensuring high-risk
    threats are reliably blocked.
    
    Attributes:
        THRESHOLDS (dict): Risk score thresholds for each threat category.
                          Values range from 0.0 (never block) to 1.0 (always block).
    
    Example:
        >>> engine = PolicyEngine()
        >>> risk_profile = {"DAN": 0.95, "AnyCode": 0.85}
        >>> decision = engine.decide("security", risk_profile)
        >>> print(decision)  # "BLOCKED" (DAN score exceeds 0.9 threshold)
    """
    
    THRESHOLDS = {
        "DAN": 0.9,      # Block if DAN jailbreak probe succeeds
        "AnyCode": 0.9,  # Block if malware generation probe succeeds
        "StartsWith": 0.9,  # Block if PII leak replay probe succeeds
    }

    @staticmethod
    def decide(category: str, risk_profile: dict) -> str:
        """
        Make security decision based on threat detection results.
        
        Evaluates the risk profile from various threat detectors against
        predefined thresholds to determine whether an AI interaction should
        be allowed or blocked. Uses a fail-secure approach where any detector
        exceeding its threshold triggers a block decision.
        
        Args:
            category (str): The interaction category being evaluated.
                           Used for contextual logging and future policy extensions.
            risk_profile (dict): Dictionary mapping detector names to risk scores.
                               Scores should be normalized between 0.0 and 1.0.
        
        Returns:
            str: Security decision, either "ALLOWED" or "BLOCKED".
                 Returns "ALLOWED" by default when no risks are detected.
        
        Example:
            >>> risk_data = {"DAN": 0.85, "AnyCode": 0.95}
            >>> decision = PolicyEngine.decide("general", risk_data)
            >>> print(decision)  # "BLOCKED" (AnyCode exceeds threshold)
            
            >>> low_risk = {"DAN": 0.3, "AnyCode": 0.2}
            >>> decision = PolicyEngine.decide("general", low_risk)
            >>> print(decision)  # "ALLOWED" (all scores below thresholds)
        """
        # If no probes were run, allow by default.
        if not risk_profile:
            return "ALLOWED"

        for detector_name, score in risk_profile.items():
            if (
                detector_name in PolicyEngine.THRESHOLDS
                and score >= PolicyEngine.THRESHOLDS[detector_name]
            ):
                print(
                    f"🚨 RUNTIME BLOCK: Probe risk '{detector_name}' score {score:.2f} exceeded threshold."
                )
                return "BLOCKED"

        return "ALLOWED"
