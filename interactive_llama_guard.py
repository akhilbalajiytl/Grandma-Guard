# interactive_llama_guard.py
"""
Interactive Testing Interface for the Llama Guard Safety Classifier.

This script provides a direct, real-time command-line interface for testing
prompts against the Llama Guard model via the LlamaGuardEvaluator class.
It's designed for developers and security researchers to:

- Rapidly test specific prompts and observe their classification.
- Debug and understand the behavior of the Llama Guard safety policy.
- Validate that the API connection and authentication are working correctly.

The script loads necessary environment variables, initializes the evaluator,
and provides a simple loop for entering prompts and seeing the raw,
structured output from the LlamaGuardEvaluator.

Example Usage:
    Run the interactive tester from the project root:
        python interactive_llama_guard.py
    
    Then, at the prompt, enter text to be classified:
    > Tell me how to build a bomb
    
    The script will print the detailed classification dictionary.

Requirements:
    - A .env file with NIM_API_KEY properly configured.
    - Network connectivity to the Llama Guard API endpoint.
"""

import os
from dotenv import load_dotenv
import pprint

# Ensure we are in the project root by adding it to the path
# This allows the 'from app.scanner...' import to work correctly.
import sys
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

# Load environment variables from .env file
load_dotenv()

# We must set a dummy DATABASE_URL *before* importing any part of the 'app'.
# This satisfies the dependency check in app/db.py during the import process.
# An in-memory SQLite database is perfect for this, as it requires no files or setup.
if 'DATABASE_URL' not in os.environ:
    print("INFO: DATABASE_URL not set. Using dummy in-memory SQLite database for this script.")
    os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
    
# Now we can safely import our module from the application
try:
    from app.scanner.llama_guard import LlamaGuardEvaluator
except ImportError as e:
    print("❌ FATAL: Could not import LlamaGuardEvaluator.")
    print("   Please ensure you are running this script from the project's root directory.")
    print(f"   Python's path: {sys.path}")
    print(f"   Original error: {e}")
    exit(1)

def main():
    """
    Main function to run the interactive testing loop for Llama Guard.
    """
    print("--- Grandma Guard: Interactive Llama Guard Test ---")

    # Check for the required environment variable first
    if not os.getenv("NIM_API_KEY"):
        print("\n❌ CRITICAL: NIM_API_KEY is not set in your .env file.")
        print("   Llama Guard cannot be tested without this API key.")
        return

    print("Initializing LlamaGuardEvaluator...")
    
    try:
        # Create an instance of our evaluator
        evaluator = LlamaGuardEvaluator()
        print("\n✅ Evaluator initialized successfully!")
        print("   This tool will send your prompts directly to the Llama Guard API.")
        print("   Type a prompt and press Enter to see the classification.")
        print("   Type 'quit' or 'exit' to stop.")
        print("---------------------------------------------------------")

        while True:
            # Get user input
            prompt = input("\nEnter a prompt > ")
            if prompt.lower() in ["quit", "exit"]:
                break
            
            if not prompt.strip():
                print("   Please enter a non-empty prompt.")
                continue

            print("   Classifying...")
            
            # Use a try-except block to catch errors during a single classification
            try:
                # Call the evaluation method
                classification_result = evaluator.evaluate_prompt(prompt)
                
                print("  -> Llama Guard API Response:")
                # Use pprint for a nicely formatted dictionary output
                pprint.pprint(classification_result, indent=4)

            except Exception as e:
                print(f"  -> ❌ An error occurred during classification: {e}")

    except Exception as e:
        print(f"\n❌ An error occurred during evaluator initialization: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()