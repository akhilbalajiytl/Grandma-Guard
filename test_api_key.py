import os
import requests
from dotenv import load_dotenv

# --- Use the same robust .env loading from our CLI script ---
project_root = os.path.dirname(os.path.abspath(__file__))
dotenv_path = os.path.join(project_root, '.env')
load_dotenv(dotenv_path=dotenv_path)

# --- Get the API Key and Define the Test ---
API_KEY = os.getenv("OPENAI_API_KEY")
ENDPOINT = "https://api.openai.com/v1/chat/completions"
MODEL = "gpt-4o" # Using a standard, capable model

print("--- API Key Tester ---")

# --- Check if the key was loaded ---
if not API_KEY:
    print("❌ ERROR: OPENAI_API_KEY not found in .env file or environment.")
    exit(1)

print(f"✅ Key loaded successfully. Testing key ending in: '...{API_KEY[-4:]}'")
print(f"   Model: {MODEL}")
print(f"   Endpoint: {ENDPOINT}")
print("-" * 20)

# --- Construct the API Request ---
headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

json_data = {
    "model": MODEL,
    "messages": [{"role": "user", "content": "Say 'Hello, world!'"}]
}

# --- Make the API Call and Print Results ---
try:
    print("Sending request to OpenAI...")
    response = requests.post(ENDPOINT, headers=headers, json=json_data, timeout=15)
    
    # Check the HTTP status code
    if response.status_code == 200:
        print("\n✅ SUCCESS! (HTTP 200 OK)")
        print("   The API key is valid and has permission to use this model.")
        print("   Response:", response.json()['choices'][0]['message']['content'])
    elif response.status_code == 401:
        print("\n❌ FAILED! (HTTP 401 Unauthorized)")
        print("   This means the API key is INVALID, EXPIRED, or has INSUFFICIENT QUOTA.")
        print("   The key itself is the problem. Please ask your supervisor to check the key's status in the OpenAI dashboard.")
        print("   Raw Error:", response.text)
    elif response.status_code == 429:
        print("\n❌ FAILED! (HTTP 429 Too Many Requests)")
        print("   This means you have hit a RATE LIMIT.")
        print("   This could be 'requests per minute' or 'tokens per minute'. Wait a minute and try again.")
        print("   Raw Error:", response.text)
    else:
        print(f"\n❌ FAILED! (HTTP {response.status_code})")
        print("   An unexpected error occurred.")
        print("   Raw Error:", response.text)

except requests.exceptions.RequestException as e:
    print(f"\n❌ FAILED! (Network Error)")
    print(f"   Could not connect to the OpenAI API. Check your internet connection.")
    print(f"   Error: {e}")