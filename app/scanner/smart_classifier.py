# app/scanner/smart_classifier.py
import os
import token
import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

# --- CONFIGURATION ---
BASE_MODEL_NAME = "microsoft/Phi-3-mini-4k-instruct"
ADAPTER_PATH = "./app/models/adapters/grandma-guard-phi3-classifier-final"

class SmartClassifier:
    def __init__(self):
        print("Loading fine-tuned SmartClassifier model...")
        
        # This config is correct for CPU-compatible 4-bit loading
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=False,
        )

        hf_token = os.getenv("HF_TOKEN")

        # Prepare the arguments for from_pretrained
        model_kwargs = {
            "quantization_config": bnb_config,
            "trust_remote_code": True,
            "token": hf_token,
        }

        # Only add device_map if a GPU is actually available
        if torch.cuda.is_available():
            print("✅ CUDA is available. Using device_map='auto'.")
            model_kwargs["device_map"] = "auto"
        else:
            print("⚠️ CUDA not available. Loading model on CPU. This will be very slow.")
            # Do NOT specify device_map for CPU loading with bitsandbytes.
            # The library will handle it correctly.
        
        base_model = AutoModelForCausalLM.from_pretrained(
            BASE_MODEL_NAME,
            **model_kwargs # Unpack the conditional arguments
        )
        
        self.tokenizer = AutoTokenizer.from_pretrained(
            BASE_MODEL_NAME, 
            trust_remote_code=True,
            token=hf_token,
        )
        self.tokenizer.pad_token = self.tokenizer.eos_token
        
        # Load the LoRA adapter onto the base model
        self.model = PeftModel.from_pretrained(base_model, ADAPTER_PATH)
        # Force the model to use the legacy cache format that is compatible
        # with the Phi-3 modeling script. This avoids the 'get_max_length' error.
        # self.model.generation_config.cache_implementation = "static"
        self.model.eval()
        
        print("✅ SmartClassifier model loaded successfully.")

    def classify(self, prompt: str) -> (str, str):
        """
        Classifies the prompt using the fine-tuned model.
        """
        input_text = f'<|user|>\nClassify the following prompt into one of three categories: BLOCK, ALLOW, or DEEP_SCAN. Prompt: "{prompt}"<|end|>\n<|assistant|>\n'
        inputs = self.tokenizer(input_text, return_tensors="pt").to("cuda")

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=5,
                eos_token_id=self.tokenizer.eos_token_id,
                use_cache=False
            )

        # The tokenizer decodes the *entire* sequence, including the prompt.
        # We need to extract the newly generated part.
        # The new tokens start right after the input tokens end.
        input_length = inputs.input_ids.shape[1]
        response_tokens = outputs[0][input_length:]
        classification = self.tokenizer.decode(response_tokens, skip_special_tokens=True).strip().upper()

        # A simple check to make sure we got a valid classification
        if classification in ["BLOCK", "ALLOW", "DEEP_SCAN"]:
            return classification, "ML_CLASSIFIER"
        else:
            # Log the unexpected output for debugging, but still return a safe default
            full_response_for_log = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            print(f"⚠️ SmartClassifier parsing error. Full response: {full_response_for_log}")
            # Default to DEEP_SCAN on any parsing error to be safe
            return "DEEP_SCAN", "ML_CLASSIFIER_PARSE_ERROR"
