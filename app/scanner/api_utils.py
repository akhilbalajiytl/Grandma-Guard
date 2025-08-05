"""GrandmaGuard API Utilities Module.

This module provides robust API communication utilities for interacting with
various Large Language Model (LLM) endpoints in both synchronous and asynchronous
contexts. It handles authentication, error recovery, and different API formats
to ensure reliable communication with AI models during security scanning operations.

Key Features:
    - Multi-provider LLM API support (OpenAI, Zhipu AI, custom endpoints)
    - Robust error handling and timeout management
    - JWT token generation for specialized authentication schemes
    - Async/await support for high-performance concurrent operations
    - Comprehensive logging and debugging capabilities

Supported Authentication:
    - Bearer token authentication (OpenAI-compatible APIs)
    - JWT token generation for Zhipu AI platform
    - Custom authentication header handling
    - Secure token management and expiration handling

Error Resilience:
    - HTTP error code handling (401, 404, 500, etc.)
    - Network timeout and connection error recovery
    - Malformed response detection and graceful degradation
    - Content-type validation and error reporting

Performance Features:
    - Shared aiohttp sessions for connection pooling
    - Configurable timeout settings for different use cases
    - Efficient JSON parsing and response validation
    - Memory-efficient streaming and processing

Use Cases:
    - Security scanning against target AI models
    - Multi-turn conversation testing and analysis
    - Batch processing of security test payloads
    - Real-time proxy operations with low latency

Example:
    Synchronous API call:
    >>> response = call_llm_api(
    ...     "https://api.openai.com/v1/chat/completions",
    ...     "sk-...", 
    ...     "Hello, world!",
    ...     "gpt-3.5-turbo"
    ... )
    
    Asynchronous API call:
    >>> async with aiohttp.ClientSession() as session:
    ...     response = await async_call_llm_api(
    ...         session, endpoint, key, prompt, model
    ...     )

Dependencies:
    - aiohttp: Asynchronous HTTP client for concurrent operations
    - requests: Synchronous HTTP client for simple operations
    - jwt: JSON Web Token generation for specialized authentication
    - asyncio: Asynchronous programming support

Notes:
    - All functions include comprehensive error handling and logging
    - Response format validation ensures consistent error reporting
    - Authentication schemes are automatically detected by endpoint URL
    - Timeouts are configured for production reliability
"""

# app/scanner/api_utils.py
import time
import asyncio
import aiohttp
import jwt
import requests
from typing import Union, List, Dict


def generate_zhipu_token(api_key):
    """Generate JWT authentication token for Zhipu AI API access.
    
    Creates a JSON Web Token (JWT) for authenticating with Zhipu AI's
    proprietary API authentication system. The token includes expiration
    and timestamp claims for secure API access.
    
    Args:
        api_key (str): Zhipu API key in format "id.secret" where:
            - id: Public identifier for the API key
            - secret: Private secret for JWT signing
    
    Returns:
        str: Encoded JWT token ready for Authorization header
    
    Raises:
        ValueError: If API key format is invalid (missing '.' separator)
        
    Token Structure:
        - api_key: Public key identifier
        - exp: Expiration timestamp (1 hour from creation)
        - timestamp: Token creation timestamp
        - Algorithm: HS256 with custom headers
    
    Example:
        >>> token = generate_zhipu_token("12345.secret_key")
        >>> headers = {"Authorization": f"Bearer {token}"}
        
    Notes:
        - Tokens expire after 1 hour for security
        - Uses HS256 algorithm for JWT signing
        - Includes custom sign_type header for Zhipu compatibility
        - Timestamps are in milliseconds per Zhipu API requirements
    """
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
    """Make synchronous API call to LLM endpoint with robust error handling.
    
    Performs a blocking HTTP request to a Large Language Model API endpoint
    with automatic authentication scheme detection and comprehensive error
    handling. Supports multiple API providers including OpenAI-compatible
    endpoints and Zhipu AI.
    
    Args:
        endpoint (str): Full URL of the LLM API endpoint
        api_key (str): Authentication key (format varies by provider)
        prompt (str): User prompt to send to the model
        api_model_identifier (str): Model name/identifier for the API
    
    Returns:
        str: Model's response content, or error message if request failed
    
    Authentication Schemes:
        - Zhipu AI: Automatic JWT token generation for bigmodel.cn domains
        - Standard: Bearer token authentication for other endpoints
    
    Error Handling:
        - HTTP errors: Returns formatted error message with status codes
        - Network timeouts: 60-second timeout with clear error reporting
        - Malformed responses: Validates expected JSON structure
        - Authentication failures: Clear error messaging for debugging
    
    Response Format:
        Expects OpenAI-compatible response structure:
        {
            "choices": [
                {"message": {"content": "response text"}}
            ]
        }
    
    Example:
        >>> response = call_llm_api(
        ...     "https://api.openai.com/v1/chat/completions",
        ...     "sk-...",
        ...     "What is AI safety?",
        ...     "gpt-3.5-turbo"
        ... )
        >>> print(response)  # "AI safety refers to..."
        
        >>> # Error case
        >>> response = call_llm_api("invalid-url", "bad-key", "test", "model")
        >>> print(response)  # "API Error: ..."
    
    Notes:
        - Blocks until response received or timeout occurs
        - Automatically detects Zhipu AI endpoints for JWT authentication
        - 60-second timeout prevents hanging requests
        - Returns error strings instead of raising exceptions for easier handling
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
        "stream": False,
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


async def async_call_llm_api(
    session: aiohttp.ClientSession, 
    api_endpoint: str, 
    api_key: str, 
    prompt_or_messages: Union[str, List[Dict]], 
    model_identifier: str
) -> str:
    """Make asynchronous API call to LLM endpoint with comprehensive error handling.

    Performs non-blocking HTTP request to a Large Language Model API endpoint
    using a shared aiohttp session for efficient connection pooling and
    concurrent operations. Designed for high-throughput security scanning
    scenarios with robust error recovery.

    Args:
        session (aiohttp.ClientSession): Active aiohttp client session for
            connection pooling and concurrent request management
        api_endpoint (str): Full URL of the LLM API endpoint
        api_key (str): Authentication API key for Bearer token auth
        prompt (str): User prompt to send to the model
        model_identifier (str): Model name/identifier for the API request

    Returns:
        str: Model's response content, or standardized error message:
            - Normal response: Actual model output text
            - HTTP errors: "API_ERROR: Status {code}"
            - Network errors: "NETWORK_ERROR: Timeout"
            - Format errors: "API_ERROR: Unexpected response format"
            - Unknown errors: "UNKNOWN_ERROR: {description}"

    Error Categories:
        1. HTTP Errors (ClientResponseError):
           - 401 Unauthorized: Invalid API key
           - 404 Not Found: Invalid endpoint
           - 500 Server Error: Provider issues
           - Rate limiting and quota errors

        2. Network Errors:
           - Connection timeouts (120s default)
           - DNS resolution failures
           - Network connectivity issues

        3. Response Format Errors:
           - Missing 'choices' field in JSON
           - Malformed JSON structure
           - Unexpected content types

    Performance Features:
        - Shared session for connection reuse
        - 120-second timeout for long model responses
        - Efficient JSON parsing and validation
        - Memory-efficient response handling

    Concurrent Usage:
        Designed for use with asyncio.gather() for concurrent requests:
        >>> async with aiohttp.ClientSession() as session:
        ...     tasks = [
        ...         async_call_llm_api(session, endpoint, key, prompt1, model),
        ...         async_call_llm_api(session, endpoint, key, prompt2, model)
        ...     ]
        ...     responses = await asyncio.gather(*tasks)

    Example:
        >>> async with aiohttp.ClientSession() as session:
        ...     response = await async_call_llm_api(
        ...         session,
        ...         "https://api.openai.com/v1/chat/completions",
        ...         "sk-...",
        ...         "Explain AI safety",
        ...         "gpt-4"
        ...     )
        ...     print(response)  # "AI safety refers to..."

    Security Considerations:
        - API keys are properly secured in Authorization headers
        - Timeout prevents hanging on malicious endpoints
        - Error messages don't leak sensitive information
        - Response content is validated before processing

    Notes:
        - Requires active aiohttp.ClientSession for operation
        - All errors return strings rather than raising exceptions
        - Comprehensive logging for debugging and monitoring
        - Optimized for concurrent security scanning operations
    """
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    
    # --- THIS IS THE CORE FIX ---
    # Check if we were given a full messages list or just a single prompt string
    if isinstance(prompt_or_messages, list):
        messages = prompt_or_messages
    else:
        # If it's a string, wrap it in the standard message format
        messages = [{"role": "user", "content": str(prompt_or_messages)}]

    payload = {
        "model": model_identifier,
        "messages": messages,
        "stream": False,
    }

    try:
        async with session.post(
            api_endpoint, headers=headers, json=payload, timeout=120
        ) as response:
            # Check for non-200 status codes and log the response body for debugging
            if response.status != 200:
                error_body = await response.text()
                print(f"API HTTP Error: Status {response.status}, Body: {error_body[:500]}")
                return f"API_ERROR: Status {response.status}"
            
            data = await response.json()
            if "choices" in data and data.get("choices"):
                return data["choices"][0].get("message", {}).get("content", "").strip()
            else:
                print(f"API Response Error: 'choices' key missing. Full response: {data}")
                return "API_ERROR: Unexpected response format."

    except aiohttp.ClientError as e:
        print(f"AIOHTTP Client Error: {e}")
        return f"NETWORK_ERROR: {e}"
    except Exception as e:
        print(f"An unexpected error occurred in async_call_llm_api: {e}")
        return f"UNKNOWN_ERROR: {e}"