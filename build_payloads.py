# build_payloads.py
import pandas as pd
import yaml

# --- Configuration ---
DATASET_PATH = "hf://datasets/GuardrailsAI/detect-jailbreak/dataset.parquet"
OUTPUT_FILE = "app/scanner/payloads.yml"
SAMPLES_PER_CATEGORY = 20
MAX_PROMPT_LENGTH = 2000

# REMOVED the get_evaluator_for_attack function as it's no longer used.


def build_yaml_from_dataset():
    print(f"Downloading dataset from {DATASET_PATH}...")
    try:
        df = pd.read_parquet(DATASET_PATH)
        print("Dataset downloaded successfully.")
    except Exception as e:
        print(f"Error downloading dataset: {e}")
        return

    jailbreaks_df = df[
        (df["is_jailbreak"] == True) & (df["prompt"].str.len() < MAX_PROMPT_LENGTH)
    ].copy()
    print(f"\nFound {len(jailbreaks_df)} suitable jailbreak prompts.")

    jailbreaks_df = jailbreaks_df.explode("tags")
    jailbreaks_df.dropna(subset=["tags"], inplace=True)

    sampled_df = (
        jailbreaks_df.groupby("tags")
        .apply(lambda x: x.sample(n=min(len(x), SAMPLES_PER_CATEGORY), random_state=42))
        .reset_index(drop=True)
    )
    print(f"\nSampled {len(sampled_df)} prompts across various categories (tags).")

    # --- Convert to our new, simpler YAML structure ---
    payloads_yaml = {}
    for index, row in sampled_df.iterrows():
        tag = row["tags"]
        prompt = row["prompt"]
        test_id = f"{tag.replace('-', '_')}_{index}"

        # The YAML structure is now much cleaner.
        # We only need the category and the payload itself.
        payloads_yaml[test_id] = {
            "category": f"Jailbreak ({tag})",
            "payloads": [prompt],
        }

    print(f"\nWriting {len(payloads_yaml)} tests to {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(payloads_yaml, f, allow_unicode=True, sort_keys=False, width=120)

    print("Done. Your new payloads.yml file is ready!")


if __name__ == "__main__":
    build_yaml_from_dataset()
