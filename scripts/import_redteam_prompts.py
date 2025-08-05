# scripts/import_redteam_prompts.py
import csv
import yaml
import argparse
from pathlib import Path

def generate_key(prompt: str, existing_keys: set) -> str:
    """Generates a unique, YAML-friendly key from a prompt."""
    # Sanitize the prompt to create a base key
    base_key = prompt.lower().strip()
    base_key = ''.join(c if c.isalnum() or c.isspace() else '' for c in base_key)
    base_key = '_'.join(base_key.split())[:50] # Limit length

    # Ensure key is unique
    key = base_key
    counter = 1
    while key in existing_keys:
        key = f"{base_key}_{counter}"
        counter += 1
    return key

def convert_csv_to_yaml(csv_path: Path, output_path: Path):
    """
    Converts a CSV file with red teaming prompts into a structured YAML file.
    
    The CSV format supports multi-turn conversations via 'prompt_follow_up_X' columns.
    The output YAML is structured for easy parsing by the Grandma Guard batch scanner.
    """
    if not csv_path.exists():
        print(f"Error: Input CSV file not found at {csv_path}")
        return

    payloads = {}
    existing_keys = set()

    print(f"Reading prompts from: {csv_path}")
    
    with open(csv_path, 'r', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        
        for row in reader:
            # Clean up the row data
            prompt = row.get('prompt', '').strip()
            if not prompt:
                continue

            undesirable = row.get('undesirable_outcome', '').strip()
            desired = row.get('desired_outcome', '').strip()

            # Collect all follow-up prompts
            follow_ups = []
            i = 1
            while True:
                follow_up_key = f'prompt_follow_up_{i}'
                if follow_up_key in row and row[follow_up_key]:
                    follow_ups.append(row[follow_up_key].strip())
                    i += 1
                else:
                    break
            
            # Generate a unique key for the YAML dictionary
            key = generate_key(prompt, existing_keys)
            existing_keys.add(key)
            
            # Build the YAML structure for this entry
            payload_entry = {
                # This category can be manually edited in the YAML later if needed
                'category': 'Red Team (Imported)',
                'payload': prompt,
                # --- New, Richer Fields ---
                'undesirable_outcome': undesirable,
                'desired_outcome': desired
            }
            
            # Add follow-ups if they exist
            if follow_ups:
                # Our new format uses 'follow_up_payloads' as a list
                payload_entry['follow_up_payloads'] = follow_ups
            
            payloads[key] = payload_entry

    if not payloads:
        print("No valid prompts found in the CSV file.")
        return

    print(f"Successfully processed {len(payloads)} unique prompts.")
    
    # Ensure the output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Writing structured YAML to: {output_path}")
    with open(output_path, 'w', encoding='utf-8') as yamlfile:
        yaml.dump(payloads, yamlfile, allow_unicode=True, default_flow_style=False, sort_keys=False)
        
    print("\n✅ Conversion complete!")
    print(f"Your new payloads file is ready at '{output_path}'.")
    print("You can now copy this file to 'app/scanner/payloads.yml' to use it in the main application.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Convert Red Team CSV prompts to Grandma Guard YAML format.")
    parser.add_argument(
        'csv_file', 
        type=Path,
        help="Path to the input CSV file (e.g., prompts.csv)"
    )
    parser.add_argument(
        '--output', 
        '-o',
        type=Path,
        default=Path('app/scanner/imported_payloads.yml'),
        help="Path for the output YAML file (default: app/scanner/imported_payloads.yml)"
    )
    
    args = parser.parse_args()
    convert_csv_to_yaml(args.csv_file, args.output)