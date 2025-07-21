# app/scanner/api_utils.py
import time

import aiohttp
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
        "stream": False,  # Explicitly disable streaming
    }

    try:
        response = requests.post(endpoint, headers=headers, json=json_data, timeout=60)
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
async def async_call_llm_api(
    session: aiohttp.ClientSession, api_endpoint, api_key, prompt, model_identifier
):
    """Asynchronously calls the LLM API using an aiohttp session."""
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    # --- ADD "stream": false TO THE PAYLOAD ---
    payload = {
        "model": model_identifier,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,  # Explicitly disable streaming
    }

    try:
        async with session.post(
            api_endpoint, headers=headers, json=payload, timeout=120
        ) as response:
            response.raise_for_status()  # This will raise an error for non-2xx statuses

            # Now, we can safely expect a JSON response
            data = await response.json()
            if "choices" in data and data.get("choices"):
                return data["choices"][0]["message"]["content"].strip()
            else:
                # Log the unexpected but valid JSON response
                print(
                    f"API Response Error: 'choices' key missing or empty. Full response: {data}"
                )
                return "API_ERROR: Unexpected response format."

    except aiohttp.ClientResponseError as e:
        # This catches HTTP errors like 401, 404, 500
        print(
            f"API HTTP Error: Status {e.status}, Message: {e.message}, URL: {e.request_info.url}"
        )
        return f"API_ERROR: Status {e.status}"
    except aiohttp.ContentTypeError as e:
        # This specifically catches the error you were seeing, in case an API ignores "stream": false
        error_text = await response.text()
        print(
            f"API Content-Type Error: Mimetype {e.headers.get('Content-Type')} is not JSON. Response text: {error_text[:200]}..."
        )
        return "API_ERROR: Unexpected content type."
    except Exception as e:
        # Catches other issues like timeouts, network problems
        print(f"Network/Request Error: {e}")
        return f"NETWORK_ERROR: {e}"
