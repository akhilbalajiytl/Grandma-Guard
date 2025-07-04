# app/scanner/api_utils.py
import time

import jwt
import requests


def generate_zhipu_token(api_key):
    """Generates a JWT token for Zhipu AI's API."""
    try:
        id, secret = api_key.split(".")
    except Exception as e:
        raise ValueError("Invalid Zhipu API Key format. Expected 'id.secret'.") from e

    payload = {
        "api_key": id,
        "exp": int(round(time.time() * 1000)) + 3600 * 1000,  # Expires in 1 hour
        "timestamp": int(round(time.time() * 1000)),
    }

    return jwt.encode(
        payload,
        secret,
        algorithm="HS256",
        headers={"alg": "HS256", "sign_type": "SIGN"},
    )


def call_llm_api(endpoint, api_key, prompt, api_model_identifier):
    """
    A robust API caller that handles different authentication schemes.
    """
    if "bigmodel.cn" in endpoint:
        try:
            token = generate_zhipu_token(api_key)
        except ValueError as e:
            return f"API Error: {e}"
    else:
        token = api_key

    headers = {"Authorization": f"Bearer {token}"}
    json_data = {
        "model": api_model_identifier,
        "messages": [{"role": "user", "content": prompt}],
    }

    try:
        response = requests.post(endpoint, headers=headers, json=json_data, timeout=30)
        response.raise_for_status()
        response_data = response.json()
        if "choices" in response_data and response_data["choices"]:
            return response_data["choices"][0]["message"]["content"]
        else:
            return (
                f"API Response Error: Unexpected format. Full response: {response_data}"
            )
    except requests.exceptions.RequestException as e:
        return f"API Error: {e}"


# NEW asynchronous version
async def async_call_llm_api(session, api_endpoint, api_key, prompt, model_identifier):
    """Asynchronously calls the LLM API using an aiohttp session."""
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": model_identifier,
        "messages": [{"role": "user", "content": prompt}],
    }

    try:
        async with session.post(
            api_endpoint, headers=headers, json=payload, timeout=120
        ) as response:
            if response.status == 200:
                data = await response.json()
                return data["choices"][0]["message"]["content"].strip()
            else:
                error_text = await response.text()
                print(f"API Error: Status {response.status}, Response: {error_text}")
                return f"API_ERROR: Status {response.status}"
    except Exception as e:
        print(f"Network/Request Error: {e}")
        return f"NETWORK_ERROR: {e}"
