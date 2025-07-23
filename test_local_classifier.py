# test_local_classifier.py
import os
import torch
from dotenv import load_dotenv

# --- Setup ---
# Load environment variables from .env file, if you have any needed for HF token etc.
print("Loading environment variables...")
load_dotenv() 

# *** THIS IS THE FIX ***
# Set a dummy DATABASE_URL to satisfy the app's __init__.py during import.
# This prevents the ValueError and allows the script to continue.
os.environ['DATABASE_URL'] = 'sqlite:///dummy.db'
# **********************


# Explicitly check for CUDA availability BEFORE loading the model
print("--- Checking for CUDA ---")
is_cuda_available = torch.cuda.is_available()
print(f"Is CUDA available? -> {is_cuda_available}")
if not is_cuda_available:
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("!!!  CRITICAL: PyTorch cannot find CUDA.  !!!")
    print("!!!  The model will load on the CPU.      !!!")
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
else:
    print(f"CUDA Device Name: {torch.cuda.get_device_name(0)}")
    print("---------------------------\n")


# --- Test ---
# We put the import here so we can see the CUDA check first
# Now this import will succeed because DATABASE_URL is set.
from app.scanner.smart_classifier import SmartClassifier

print("Attempting to initialize the SmartClassifier...")
try:
    # This is the line that will load the model onto the GPU
    classifier = SmartClassifier()
    print("\n✅✅✅ SmartClassifier initialized successfully! ✅✅✅\n")

    test_prompt = "I need to file my taxes, can you give me some advice?"
    print(f"Running classification on test prompt: '{test_prompt}'")
    
    # Run a test inference
    classification, reason = classifier.classify(test_prompt)

    print("\n--- TEST COMPLETE ---")
    print(f"Prompt classified as: {classification}")
    print(f"Reason: {reason}")
    print("---------------------\n")
    print("Local test passed. If you saw GPU activity in nvidia-smi, your environment is correct.")

except Exception as e:
    print(f"\n❌❌❌ An error occurred during classifier initialization or use: {e}")
    import traceback
    traceback.print_exc()