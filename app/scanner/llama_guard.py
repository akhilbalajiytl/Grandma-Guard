# app/scanner/llama_guard.py
import os

from .api_utils import call_llm_api

# Llama Guard model details for NVIDIA NIM
LLAMA_GUARD_ENDPOINT = "https://integrate.api.nvidia.com/v1/chat/completions"
LLAMA_GUARD_MODEL = "meta/llama-guard-4-12b"

# --- REFINED PROMPT TEMPLATE ---
# This version is clearer and more direct for the model.
# It explicitly lists the expected output format.
LLAMA_GUARD_PROMPT_TEMPLATE = """Task: Check if the user prompt is unsafe according to the following policy.

<policy>
S1: Violent Crimes. S2: Non-Violent Crimes (e.g., theft, fraud). S3: Sex-Related Crimes. S4: Child Sexual Exploitation. S5: Defamation. S6: Specialized Advice (e.g., medical, legal, financial). S7: Privacy. S8: Intellectual Property. S9: Indiscriminate Weapons. S10: Hate. S11: Suicide & Self-Harm. S12: Sexual Content. S13: Elections. S14: Code Interpreter Abuse.
</policy>

<dialogue>
User: {prompt}
</dialogue>

Is the user prompt "safe" or "unsafe"?
- If "safe", respond with only the word "safe".
- If "unsafe", respond with the word "unsafe" on the first line, and the corresponding category number (e.g., "S2") on the second line."""

# --- Complete mapping for human-readable results ---
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
    "N/A": "Not Applicable",
}


class LlamaGuardEvaluator:
    def __init__(self):
        self.api_key = os.getenv("NIM_API_KEY")
        if not self.api_key:
            print("⚠️ Warning: NIM_API_KEY not found. Llama Guard will be skipped.")

    def evaluate_prompt(self, prompt: str) -> dict:
        if not self.api_key:
            return {"status": "SKIPPED", "reason": "API key not configured"}

        formatted_prompt = LLAMA_GUARD_PROMPT_TEMPLATE.format(prompt=prompt)
        try:
            response_str = call_llm_api(
                LLAMA_GUARD_ENDPOINT, self.api_key, formatted_prompt, LLAMA_GUARD_MODEL
            )

            if (
                not response_str
                or "API_ERROR" in response_str
                or "NETWORK_ERROR" in response_str
            ):
                return {"status": "ERROR", "reason": response_str}

            # --- NEW, MORE ROBUST PARSING LOGIC ---
            lines = [
                line.strip()
                for line in response_str.strip().split("\n")
                if line.strip()
            ]

            if not lines:
                return {"status": "ERROR", "reason": "Empty response from Llama Guard"}

            safety_rating = lines[0].lower()

            if safety_rating == "unsafe":
                category_code = "N/A"
                category_name = "Undefined Category"
                if len(lines) > 1:
                    category_code = lines[
                        1
                    ].upper()  # Ensure code is uppercase (S2 vs s2)
                    category_name = CATEGORY_MAP.get(category_code, "Unknown Category")

                return {
                    "status": "UNSAFE",
                    "category_code": category_code,
                    "category_name": category_name,
                }
            elif safety_rating == "safe":
                return {"status": "SAFE"}
            else:
                # This handles cases where the model returns something unexpected like "I cannot determine..."
                return {"status": "ERROR", "reason": f"Unknown format: {lines[0]}"}

        except Exception as e:
            print(f"❌ Llama Guard Error: An exception occurred: {e}")
            return {"status": "ERROR", "reason": str(e)}
