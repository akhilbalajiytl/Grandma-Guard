# merge_model_gpu.py
import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

BASE_MODEL_NAME = "microsoft/Phi-3-mini-4k-instruct"
ADAPTER_PATH = "./grandma-guard-phi3-classifier-final" # Use your latest trained adapter
MERGED_MODEL_PATH = "./phi3-mini-classifier-merged" # The output directory for the new model

# --- IMPORTANT ---
# Set the device explicitly from the start
device = "cuda" if torch.cuda.is_available() else "cpu"
if device == "cpu":
    print("CRITICAL: CUDA not found. This script requires a GPU to merge efficiently.")
    exit()

print(f"Using device: {device}")
print(f"Loading base model: {BASE_MODEL_NAME} directly to GPU")

# Load the base model directly onto the GPU to minimize CPU RAM usage
base_model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL_NAME,
    torch_dtype=torch.float16,
    trust_remote_code=True,
    device_map=device # Explicitly load to GPU
)
tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_NAME, trust_remote_code=True)

print(f"Loading PEFT adapter: {ADAPTER_PATH}")
# Load the PEFT model, which will also be on the GPU
model = PeftModel.from_pretrained(base_model, ADAPTER_PATH)

print("Merging adapter into the base model (on GPU)...")
# The merge_and_unload() command will now operate on GPU tensors
model = model.merge_and_unload()
print("Merge complete.")

print(f"Saving merged model to: {MERGED_MODEL_PATH}")
# The model is on the GPU, but save_pretrained handles it correctly
model.save_pretrained(MERGED_MODEL_PATH)
tokenizer.save_pretrained(MERGED_MODEL_PATH)

print("\n✅ Merged model saved successfully!")