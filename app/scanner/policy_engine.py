# app/scanner/policy_engine.py


class PolicyEngine:
    """Makes a real-time decision based on a combination of risk factors."""

    # Block immediately if any of these high-confidence detectors fire.
    IMMEDIATE_BLOCK_THRESHOLDS = {
        "dan_jailbreak": 0.9,
        "known_bad_signature": 0.9,
        "xss_vuln": 0.9,
        "prompt_injection": 0.9,
    }

    # We also need to know if the prompt ITSELF is risky.
    # We can use a simple keyword check for this.
    RISKY_PROMPT_KEYWORDS = [
        "bomb",
        "kill",
        "how to make",
        "illegal",
        "stolen",
        "exploit",
        "virus",
    ]

    @staticmethod
    def decide(prompt: str, risk_profile: dict) -> str:
        # Rule 1: Immediate block on high-confidence technical attacks
        for risk, score in risk_profile.items():
            if (
                risk in PolicyEngine.IMMEDIATE_BLOCK_THRESHOLDS
                and score >= PolicyEngine.IMMEDIATE_BLOCK_THRESHOLDS[risk]
            ):
                print(
                    f"🚨 RUNTIME BLOCK [Rule 1]: High-confidence detector '{risk}' fired."
                )
                return "BLOCKED"

        # Rule 2: If the prompt looks risky AND the model failed to refuse, block it.
        # This prevents blocking helpful answers to safe prompts.
        prompt_is_risky = any(
            keyword in prompt.lower() for keyword in PolicyEngine.RISKY_PROMPT_KEYWORDS
        )
        model_did_not_refuse = risk_profile.get("no_refusal", 0.0) > 0.9

        if prompt_is_risky and model_did_not_refuse:
            print(
                "🚨 RUNTIME BLOCK [Rule 2]: Risky prompt keywords found and model failed to refuse."
            )
            return "BLOCKED"

        # If no rules were triggered, allow the response.
        return "ALLOWED"
