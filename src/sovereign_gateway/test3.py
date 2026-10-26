
import asyncio
import os
import time
import httpx
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path.cwd() / ".env", override=True)

base = os.getenv("ORDS_BASE_URL", "").rstrip("/")
client_id = os.getenv("ORDS_CLIENT_ID")
client_secret = os.getenv("ORDS_CLIENT_SECRET")

timeout = httpx.Timeout(
    connect=15,
    read=35,
    write=15,
    pool=10
)


async def test_request(client, label, method, url, **kwargs):
    print(f"\n--- {label} ---")
    start = time.perf_counter()

    try:
        response = await client.request(method, url, **kwargs)

        print("HTTP status:", response.status_code)
        print(f"Elapsed: {time.perf_counter() - start:.2f}s")
        
        if response.status_code != 200:
            try:
                data = response.json()
                print("Error:", data.get("error", "HTTP response received"))
            except ValueError:
                print("Response received (body omitted)")
        else:
            print("Request successful")

        return response

    except httpx.TimeoutException as exc:
        print("TIMEOUT:", type(exc).__name__)
    except httpx.RequestError as exc:
        print("NETWORK ERROR:", type(exc).__name__)

    print(f"Elapsed: {time.perf_counter() - start:.2f}s")
    return None


async def main():

    if not base or not client_id or not client_secret:
        print("Missing ORDS configuration")
        return

    # Test 1: Does HTTPX reach the protected ORDS endpoint?
    async with httpx.AsyncClient(
        timeout=timeout,
        trust_env=False,
        follow_redirects=False
    ) as client:

        await test_request(
            client,
            "TEST 1: Unauthenticated ORDS endpoint",
            "GET",
            f"{base}/ai-gateway/departments/"
        )

    # Test 2: OAuth using default HTTPX headers.
    async with httpx.AsyncClient(
        timeout=timeout,
        trust_env=False,
        follow_redirects=False
    ) as client:

        await test_request(
            client,
            "TEST 2: OAuth with default HTTPX headers",
            "POST",
            f"{base}/oauth/token",
            auth=(client_id, client_secret),
            data={"grant_type": "client_credentials"},
            headers={"Accept": "application/json"}
        )

    # Test 3: OAuth using Postman-like request headers.
    async with httpx.AsyncClient(
        timeout=timeout,
        trust_env=False,
        follow_redirects=False
    ) as client:

        await test_request(
            client,
            "TEST 3: OAuth with Postman-like headers",
            "POST",
            f"{base}/oauth/token",
            auth=(client_id, client_secret),
            data={"grant_type": "client_credentials"},
            headers={
                "Accept": "*/*",
                "User-Agent": "PostmanRuntime/7.49.1"
            }
        )


asyncio.run(main())
