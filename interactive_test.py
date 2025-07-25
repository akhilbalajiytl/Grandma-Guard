# interactive_test.py
import torch
import os
from dotenv import load_dotenv

# --- IMPORTANT ---
# This script must be run from the root of your project directory
# so that the relative path to the 'app' module works correctly.

# Load environment variables if needed
load_dotenv()

# We need to set a dummy DATABASE_URL to prevent the app/__init__.py from crashing
# when we import the SmartClassifier.
os.environ['DATABASE_URL'] = 'sqlite:///dummy.db'

# Now, we can safely import our classifier
from app.scanner.smart_classifier import SmartClassifier

def main():
    """
    Main function to run the interactive test loop.
    """
    print("--- Grandma Guard: Interactive SmartClassifier Test ---")
    
    # Check for CUDA availability first
    if not torch.cuda.is_available():
        print("\n❌ CRITICAL: CUDA is not available. This test requires a GPU.")
        print("Please check your NVIDIA drivers and PyTorch installation.")
        return

    print(f"\nFound GPU: {torch.cuda.get_device_name(0)}")
    print("Initializing the SmartClassifier... (This may take a moment)")

    try:
        classifier = SmartClassifier()
        print("\n✅ Classifier initialized successfully!")
        print("Type a prompt and press Enter to see the classification.")
        print("Type 'quit' or 'exit' to stop.")
        print("----------------------------------------------------")

        while True:
            prompt = input("\nEnter a prompt > ")
            if prompt.lower() in ["quit", "exit"]:
                break
            
            print("Classifying...")
            
            # Use a try-except block to catch any errors during a single inference
            try:
                classification, reason = classifier.classify(prompt)
                print(f"  -> Result: {classification} (Reason: {reason})")
            except Exception as e:
                print(f"  -> ❌ An error occurred during classification: {e}")

    except Exception as e:
        print(f"\n❌ An error occurred during classifier initialization: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()