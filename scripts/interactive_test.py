"""Interactive Testing Interface for GrandmaGuard SmartClassifier.

This module provides an interactive command-line interface for testing the
GrandmaGuard SmartClassifier in real-time. It allows security researchers and
developers to manually test prompts against the classification system and
observe the results immediately.

The script initializes the SmartClassifier with GPU acceleration (if available)
and provides a simple REPL (Read-Eval-Print Loop) for prompt testing. It's
designed for ad-hoc testing, debugging, and validation of the classifier's
behavior on specific inputs.

Features:
    - Real-time prompt classification testing
    - GPU acceleration detection and validation
    - Error handling for individual classification attempts
    - Interactive command-line interface
    - Graceful shutdown with quit/exit commands

Example:
    Run the interactive tester:
        python interactive_test.py
    
    Then enter prompts at the prompt to see classification results.

Requirements:
    - CUDA-compatible GPU for optimal performance
    - Trained SmartClassifier model available
    - Proper environment configuration

Note:
    This script must be run from the project root directory to ensure
    proper module path resolution for the app package.
"""

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
    """Run the interactive testing loop for the SmartClassifier.
    
    This function provides the main interactive interface for testing prompts
    against the GrandmaGuard classification system. It:
    
    1. Checks for CUDA GPU availability
    2. Initializes the SmartClassifier model
    3. Provides a command-line interface for prompt testing
    4. Handles errors gracefully during classification
    5. Allows graceful exit with 'quit' or 'exit' commands
    
    The function runs in a continuous loop, accepting user input and
    displaying classification results until the user chooses to exit.
    
    Raises:
        SystemExit: If CUDA is not available when GPU acceleration is required
        Exception: If classifier initialization fails
        
    Note:
        Individual classification errors are caught and displayed without
        terminating the interactive session.
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
    """Main execution block for the interactive classifier testing interface.
    
    Executes the main testing loop when the script is run directly,
    providing an interactive interface for testing the SmartClassifier.
    """
    main()