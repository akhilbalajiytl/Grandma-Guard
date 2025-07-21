# app/scanner/smart_classifier.py
import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

# --- CONFIGURATION ---
# These must match what you used for training
BASE_MODEL_NAME = "microsoft/Phi-3-mini-4k-instruct"
ADAPTER_PATH = "./grandma-guard-phi3-classifier-final"  # Path to your trained adapter


class SmartClassifier:
    def __init__(self):
        print("Loading fine-tuned SmartClassifier model...")

        # We can still use 4-bit for fast inference
        bnb_config = BitsAndBytesConfig(load_in_4bit=True)

        base_model = AutoModelForCausalLM.from_pretrained(
            BASE_MODEL_NAME,
            quantization_config=bnb_config,
            trust_remote_code=True,
            device_map="auto",
        )

        self.tokenizer = AutoTokenizer.from_pretrained(
            BASE_MODEL_NAME, trust_remote_code=True
        )
        self.tokenizer.pad_token = self.tokenizer.eos_token

        # --- Load the LoRA adapter onto the base model ---
        self.model = PeftModel.from_pretrained(base_model, ADAPTER_PATH)
        self.model.eval()  # Set the model to evaluation mode

        print("✅ SmartClassifier model loaded successfully.")

    def classify(self, prompt: str) -> (str, str):
        """
        Classifies the prompt using the fine-tuned model.
        """
        # Format the input exactly as we did for training
        input_text = f'<|user|>\nClassify the following prompt into one of three categories: BLOCK, ALLOW, or DEEP_SCAN. Prompt: "{prompt}"<|end|>\n<|assistant|>\n'

        inputs = self.tokenizer(input_text, return_tensors="pt").to(
            "cuda"
        )  # Assuming GPU

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs, max_new_tokens=5, eos_token_id=self.tokenizer.eos_token_id
            )

        response_text = self.tokenizer.decode(outputs[0], skip_special_tokens=True)

        # Extract just the classification from the full response
        # The model will output the full text, including our prompt, then its answer
        classification = response_text.split("<|assistant|>")[1].strip().upper()

        if "BLOCK" in classification:
            return "BLOCK", "ML_CLASSIFIER"
        elif "DEEP_SCAN" in classification:
            return "DEEP_SCAN", "ML_CLASSIFIER"
        else:
            return "ALLOW", "ML_CLASSIFIER"


# You would then integrate this SmartClassifier into your runtime_scanner,
# replacing the TriageClassifier.
