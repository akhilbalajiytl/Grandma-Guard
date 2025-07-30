"""Fine-tuning Module for GrandmaGuard Prompt Classifier.

This module fine-tunes a Microsoft Phi-3 language model using LoRA (Low-Rank Adaptation)
to create a specialized classifier for detecting harmful or jailbreak prompts. The
fine-tuned model serves as a core component of the GrandmaGuard security system.

The module implements memory-efficient training using:
    - 4-bit quantization to reduce memory usage
    - LoRA adapters for parameter-efficient fine-tuning
    - Mixed-precision training for performance
    - Gradient accumulation for stable training

Features:
    - Automated dataset loading from JSONL format
    - Configurable LoRA parameters for adapter training
    - Memory-optimized training pipeline
    - Checkpoint saving for model recovery

Example:
    Run the fine-tuning process:
        python finetune_classifier.py
    
    This will create a LoRA adapter trained on the classification dataset.

Constants:
    BASE_MODEL_NAME: The foundation model to fine-tune (Phi-3-mini)
    DATASET_NAME: Path to the training dataset in JSONL format
    NEW_ADAPTER_NAME: Output directory name for the trained adapter

Requirements:
    - CUDA-compatible GPU recommended for training
    - Training dataset in proper instruction format
    - Sufficient disk space for model checkpoints

Note:
    The training uses a small number of steps by default for testing.
    Increase max_steps to 500-1000 for production training.
"""

import torch
from datasets import load_dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    TrainingArguments,
)
from trl import SFTTrainer

# --- CONFIGURATION ---
BASE_MODEL_NAME = "microsoft/Phi-3-mini-4k-instruct"
DATASET_NAME = "app/finetune_dataset.jsonl"
NEW_ADAPTER_NAME = (
    "grandma-guard-phi3-classifier"  # The name for our trained LoRA adapter
)


def finetune():
    """Load base model, apply LoRA, and fine-tune on classification dataset.
    
    This function implements the complete fine-tuning pipeline:
    1. Loads the training dataset from JSONL format
    2. Configures 4-bit quantization for memory efficiency
    3. Loads the base Phi-3 model and tokenizer
    4. Sets up LoRA adapters for parameter-efficient training
    5. Configures training arguments for optimal performance
    6. Executes the training loop using SFTTrainer
    7. Saves the trained adapter for later use
    
    The training uses mixed-precision and gradient accumulation to balance
    memory usage with training stability. Checkpoints are saved periodically
    to prevent loss of progress.
    
    Raises:
        RuntimeError: If CUDA is not available when expected
        FileNotFoundError: If the training dataset is not found
        torch.cuda.OutOfMemoryError: If GPU memory is insufficient
        
    Note:
        The function expects the dataset to be in instruction format with
        proper prompt/response pairs for classification training.
    """
    print(f"Starting fine-tuning process for model: {BASE_MODEL_NAME}")

    # --- 1. Load the dataset ---
    print(f"Loading dataset from {DATASET_NAME}...")
    dataset = load_dataset("json", data_files=DATASET_NAME, split="train")

    # --- 2. Configure Quantization (to save memory) ---
    # Load the model in 4-bit precision
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )

    # --- 3. Load the Model and Tokenizer ---
    print("Loading base model and tokenizer...")
    model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL_NAME,
        quantization_config=bnb_config,
        trust_remote_code=True,  # Phi-3 requires this
        device_map="auto",  # Automatically use GPU if available
    )
    model.config.use_cache = False  # Recommended for training

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_NAME, trust_remote_code=True)
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    # --- 4. Configure LoRA ---
    print("Configuring LoRA adapter...")
    model = prepare_model_for_kbit_training(model)
    lora_config = LoraConfig(
        r=16,
        lora_alpha=32,
        target_modules="all-linear",  # Target all linear layers for simplicity
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, lora_config)

   # --- 5. Configure Training ---
    training_args = TrainingArguments(
        output_dir=f"./{NEW_ADAPTER_NAME}",
        per_device_train_batch_size=2,
        gradient_accumulation_steps=4,
        learning_rate=2e-4,
        max_steps=100, # A small number for a quick test run. Increase to 500-1000 for a real training.
        logging_steps=10,
        fp16=True, # Use mixed-precision training
        optim="paged_adamw_8bit",
        save_strategy="steps",
        save_steps=50,
        report_to="none", # Disable wandb/tensorboard reporting for simplicity
    )

    # --- 6. Create and Start the Trainer ---
    print("Initializing SFTTrainer...")
    trainer = SFTTrainer(
        model=model,
        train_dataset=dataset,
        peft_config=lora_config,
        args=training_args,
    )

    print("Starting training...")
    trainer.train()
    
    print("Training complete.")
    
    # --- 7. Save the final adapter ---
    print(f"Saving LoRA adapter to ./{NEW_ADAPTER_NAME}-final")
    trainer.model.save_pretrained(f"./{NEW_ADAPTER_NAME}-final")
    
    print("\n✅ Fine-tuning complete! Your new LoRA adapter is saved.")


if __name__ == "__main__":
    """Main execution block for the fine-tuning process.
    
    Executes the complete fine-tuning pipeline when the script is run directly.
    This includes loading the dataset, configuring the model, and training
    the LoRA adapter for prompt classification.
    """
    finetune()
