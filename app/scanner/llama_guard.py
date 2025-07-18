# app/scanner/llama_guard.py
import os

from .api_utils import call_llm_api

# Llama Guard model details for NVIDIA NIM
LLAMA_GUARD_ENDPOINT = "https://integrate.api.nvidia.com/v1/chat/completions"
LLAMA_GUARD_MODEL = "meta/llama-guard-4-12b"

# Clarified the output format expected: "safe" or "unsafe\nS<number>".
LLAMA_GUARD_PROMPT_TEMPLATE = """Task: Check if the user's prompt is unsafe content based on the policy.
Policy:
S1: Violent Crimes. S2: Non-Violent Crimes (e.g., theft, fraud). S3: Sex-Related Crimes. S4: Child Sexual Exploitation. 
S5: Defamation. S6: Specialized Advice (e.g., medical, legal, financial). S7: Privacy. 
S8: Intellectual Property. S9: Indiscriminate Weapons. S10: Hate. S11: Suicide & Self-Harm. 
S12: Sexual Content. S13: Elections. S14: Code Interpreter Abuse.

<BEGIN DIALOGUE>
User: {prompt}
<END DIALOGUE>

Is the user's prompt "safe" or "unsafe"?
If "unsafe", which policy category does it violate?
Respond with only the word "safe" or the word "unsafe" on the first line, and the category number (e.g., "S2") on the second line if it is unsafe."""

# --- NEW: Mapping for human-readable results ---
CATEGORY_MAP = {
    "S1": "Violent Crimes",
    "S2": "Non-Violent Crimes",
    "S3": "Sex-Related Crimes",
    "S4": "Child Sexual Exploitation",
    "S5": "Defamation",
    "S6": "Specialized Advice",
    "S7": "Privacy",
    "S8": "Intellectual Property",
    "S9": "Indiscriminate Weapons",
    "S10": "Hate",
    "S11": "Suicide & Self-Harm",
    "S12": "Sexual Content",
    "S13": "Elections",
    "S14": "Code Interpreter Abuse",
}


class LlamaGuardEvaluator:
    """
    Uses Llama Guard via an API endpoint to evaluate the safety of a prompt.
    """

    def __init__(self):
        self.api_key = os.getenv("NIM_API_KEY")
        if not self.api_key:
            print("⚠️ Warning: NIM_API_KEY not found. Llama Guard will be skipped.")

    def evaluate_prompt(self, prompt: str) -> dict:
        """
        Evaluates a user prompt for safety using Llama Guard.
        Handles the new string-based output format.
        """
        if not self.api_key:
            return {"status": "SKIPPED", "reason": "API key not configured"}

        formatted_prompt = LLAMA_GUARD_PROMPT_TEMPLATE.format(prompt=prompt)

        try:
            # --- FIX 2: We no longer expect JSON, just a string from call_llm_api ---
            response_str = call_llm_api(
                LLAMA_GUARD_ENDPOINT, self.api_key, formatted_prompt, LLAMA_GUARD_MODEL
            )

            if (
                not response_str
                or "API_ERROR" in response_str
                or "NETWORK_ERROR" in response_str
            ):
                return {"status": "ERROR", "reason": response_str}

            # --- NEW PARSING LOGIC ---
            # The response is a multi-line string. Split it into lines.
            lines = response_str.strip().split("\n")

            # The first line should be the safety rating.
            safety_rating = lines[0].strip().lower()

            if safety_rating == "unsafe":
                category_code = lines[1].strip() if len(lines) > 1 else "N/A"
                # Use the map to get the full category name
                category_name = CATEGORY_MAP.get(category_code, "Unknown Category")
                return {
                    "status": "UNSAFE",
                    "category_code": category_code,
                    "category_name": category_name,  # <-- Add human-readable name
                }
            elif safety_rating == "safe":
                return {"status": "SAFE"}
            else:
                return {"status": "ERROR", "reason": "Unknown format"}
        except Exception as e:
            return {"status": "ERROR", "reason": str(e)}
