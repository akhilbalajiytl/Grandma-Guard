# build_payloads.py
import pandas as pd
import yaml

# --- Configuration ---
DATASET_PATH = "hf://datasets/GuardrailsAI/detect-jailbreak/dataset.parquet"
OUTPUT_FILE = "app/scanner/payloads.yml"
SAMPLES_PER_CATEGORY = 20  # How many prompts to take from each attack type
MAX_PROMPT_LENGTH = 2000  # Ignore extremely long prompts


def get_evaluator_for_attack(tag):  # Parameter is now a single tag
    """Maps a tag to one of our existing evaluators."""
    if "obfuscation" in tag or "program-execution" in tag:
        return "detect_refusal"
    if "xss" in str(tag).lower():
        return "detect_javascript"
    # Default to our most robust baseline checker
    return "detect_refusal"


def build_yaml_from_dataset():
    print(f"Downloading dataset from {DATASET_PATH}...")
    try:
        df = pd.read_parquet(DATASET_PATH)
        print("Dataset downloaded successfully.")
    except Exception as e:
        print(f"Error downloading dataset: {e}")
        return

    print("\nDataset Columns:", df.columns.tolist())

    # Filter for prompts that are actual jailbreaks and not too long
    jailbreaks_df = df[
        (df["is_jailbreak"] == True) & (df["prompt"].str.len() < MAX_PROMPT_LENGTH)
    ].copy()

    print(f"\nFound {len(jailbreaks_df)} suitable jailbreak prompts.")

    # --- THIS IS THE FIX: Use the correct column name 'tags' ---
    # The 'tags' column contains the list of attack types.
    print("Exploding DataFrame by 'tags' column...")
    # The .explode() method will create a new row for each tag in the list.
    jailbreaks_df = jailbreaks_df.explode("tags")

    # Remove any rows where the tag might be missing after exploding
    jailbreaks_df.dropna(subset=["tags"], inplace=True)

    # --- Sample the data ---
    # We group by the 'tags' column now
    # Using a lambda to handle cases where a group is smaller than our sample size
    sampled_df = (
        jailbreaks_df.groupby("tags")
        .apply(lambda x: x.sample(n=min(len(x), SAMPLES_PER_CATEGORY), random_state=42))
        .reset_index(drop=True)
    )

    print(f"\nSampled {len(sampled_df)} prompts across various categories (tags).")

    # --- Convert to our YAML structure ---
    payloads_yaml = {}
    for index, row in sampled_df.iterrows():
        # Use the correct 'tags' column
        tag = row["tags"]
        prompt = row["prompt"]

        # Create a unique ID for each test
        test_id = f"{tag.replace('-', '_')}_{index}"

        payloads_yaml[test_id] = {
            "category": f"Jailbreak ({tag})",
            "evaluator": get_evaluator_for_attack(tag),
            "payloads": [prompt],
        }

    # --- Write to YAML file ---
    print(f"\nWriting {len(payloads_yaml)} tests to {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(payloads_yaml, f, allow_unicode=True, sort_keys=False, width=120)

    print("Done. Your new payloads.yml file is ready!")


# Make sure the main call is correct
if __name__ == "__main__":
    build_yaml_from_dataset()
