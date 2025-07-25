# app/scanner/smart_classifier.py (Final API Version)
import requests
import json
import os # Keep os import in case other files expect it

# --- CONFIGURATION ---
# These are now for the API client, not for loading a local model
OLLAMA_API_ENDPOINT = "http://localhost:11434/api/generate"
MODEL_NAME = "grandma-guard-classifier" # The name you created in Ollama

class SmartClassifier:
    def __init__(self):
        """
        Initializes the SmartClassifier in API mode.
        This is now a lightweight client that connects to a running Ollama server.
        No models are loaded here.
        """
        print("✅ SmartClassifier (API Mode) is initialized and ready.")
        # We can add a check here to see if the Ollama server is reachable at startup
        try:
            # A simple HEAD request to see if the server is alive
            requests.head("http://localhost:11434", timeout=3)
            print("  -> Successfully connected to Ollama server.")
        except requests.exceptions.RequestException:
            print("  -> ⚠️ WARNING: Could not connect to the Ollama server at http://localhost:11434.")
            print("     Please ensure the Ollama server is running with your model loaded.")

    def classify(self, prompt: str) -> (str, str):
        """
        Classifies the prompt by calling the local Ollama API.
        This method has the exact same signature (inputs and outputs) as the old version.
        
        Returns:
            tuple[str, str]: A tuple containing the classification and the reason.
        """
        # Prepare the prompt exactly as the model expects from its Modelfile
        # We only need to send the core user prompt, as the SYSTEM prompt is
        # handled by Ollama itself.
        # The prompt format is based on '<|user|>\n{{ .Prompt }}<|end|>\n<|assistant|>\n'
        # with the system prompt applied before.
        full_prompt_for_api = f'Classify the following prompt into one of three categories: BLOCK, ALLOW, or DEEP_SCAN. Prompt: "{prompt}"'

        try:
            # Prepare the JSON payload for the Ollama API
            payload = {
                "model": MODEL_NAME,
                "prompt": full_prompt_for_api,
                "stream": False, # We want the full response at once
                "options": {
                    "num_predict": 5 # Limit the model to generate only a few tokens
                }
            }
            
            # Make the API call
            response = requests.post(OLLAMA_API_ENDPOINT, json=payload, timeout=60)
            response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)

            # Parse the JSON response
            response_data = response.json()
            classification = response_data.get("response", "").strip().upper()

            # Clean up the classification, as the model might add extra text
            if "BLOCK" in classification:
                final_class = "BLOCK"
            elif "DEEP_SCAN" in classification:
                final_class = "DEEP_SCAN"
            elif "ALLOW" in classification:
                final_class = "ALLOW"
            else:
                # Handle cases where the model gives an unexpected response
                print(f"⚠️ SmartClassifier API parsing error. Full response: {classification}")
                return "DEEP_SCAN", "ML_CLASSIFIER_PARSE_ERROR"

            return final_class, "ML_CLASSIFIER_API"

        except requests.exceptions.RequestException as e:
            print(f"❌ Could not connect to Ollama API: {e}")
            # Default to DEEP_SCAN if the model API is down, for safety
            return "DEEP_SCAN", "API_CONNECTION_ERROR"