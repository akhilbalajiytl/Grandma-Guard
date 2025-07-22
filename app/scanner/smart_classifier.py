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
        self.model.eval()
        
        print("✅ SmartClassifier model loaded successfully.")

    def classify(self, prompt: str) -> (str, str):
        """
        Classifies the prompt using the fine-tuned model.
        """
        input_text = f"<|user|>\nClassify the following prompt into one of three categories: BLOCK, ALLOW, or DEEP_SCAN. Prompt: \"{prompt}\"" \
             f"<|end|>\n<|assistant|>\n"

        # Determine the device to send the inputs to. The model knows its device.
        device = self.model.device
        inputs = self.tokenizer(input_text, return_tensors="pt").to(device)

        with torch.no_grad():
            outputs = self.model.generate(**inputs, max_new_tokens=5,
                                          eos_token_id=self.tokenizer.eos_token_id)

        response_text = self.tokenizer.decode(outputs[0], skip_special_tokens=True)

        # Extract just the classification from the full response
        try:
            classification = response_text.split("<|assistant|>")[1].strip().upper()
        except IndexError:
            # Handle cases where the model output is not in the expected format
            print(f"⚠️ SmartClassifier parsing error. Full response: {response_text}")
            return "DEEP_SCAN", "ML_CLASSIFIER_PARSE_ERROR" # Default to a safe action

        if "BLOCK" in classification:
            return "BLOCK", "ML_CLASSIFIER"
        elif "DEEP_SCAN" in classification:
            return "DEEP_SCAN", "ML_CLASSIFIER"
        else:
            return "ALLOW", "ML_CLASSIFIER"
