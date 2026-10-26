
import asyncio
import os
import time
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv(Path.cwd() / ".env", override=True)

BASE_URL = os.getenv("ORDS_BASE_URL", "").strip().rstrip("/")
CLIENT_ID = os.getenv("ORDS_CLIENT_ID", "").strip()
CLIENT_SECRET = os.getenv("ORDS_CLIENT_SECRET", "").strip()

async def main():

    if not all([BASE_URL, CLIENT_ID, CLIENT_SECRET]):
        print("ERROR: ORDS configuration missing")
        return

    print("HTTPX version:", httpx.__version__)
    print("Base URL configured:", bool(BASE_URL))
    print("Client ID configured:", bool(CLIENT_ID))
    print("Client Secret configured:", bool(CLIENT_SECRET))

    timeout = httpx.Timeout(
        connect=15,
        read=60,
        write=30,
        pool=10
    )

    async with httpx.AsyncClient(
        timeout=timeout,
        trust_env=False,
        follow_redirects=False
    ) as client:

        # Test 1: OAuth token request
        print("\nTesting OAuth authentication...")

        start = time.perf_counter()

        try:
            response = await client.post(
                f"{BASE_URL}/oauth/token",
                auth=(CLIENT_ID, CLIENT_SECRET),
                data={
                    "grant_type": "client_credentials"
                },
                headers={
                    "Accept": "application/json"
                }
            )

            print("OAuth HTTP status:", response.status_code)
            print(f"Elapsed: {time.perf_counter() - start:.2f} seconds")

            if response.status_code != 200:
                try:
                    error = response.json()
                    print("OAuth error:", error.get("error"))
                    print("Description:", error.get("error_description"))
                except ValueError:
                    print("Response is not valid JSON")

                return

            result = response.json()
            access_token = result.get("access_token")

            if not access_token:
                print("ERROR: Access token missing from response")
                return

            print("OAuth authentication: SUCCESS")
            print("Token type:", result.get("token_type"))
            print("Token value: hidden")

        except httpx.TimeoutException as exc:
            print("TIMEOUT:", type(exc).__name__)
            return

        except httpx.RequestError as exc:
            print("NETWORK ERROR:", type(exc).__name__)
            return

        # Test 2: Oracle REST API
        print("\nTesting Oracle departments endpoint...")

        start = time.perf_counter()

        try:
            response = await client.get(
                f"{BASE_URL}/ai-gateway/departments/",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json"
                }
            )

            print("ORDS HTTP status:", response.status_code)
            print(f"Elapsed: {time.perf_counter() - start:.2f} seconds")

            if response.status_code == 200:
                data = response.json()
                print("ORDS connection: SUCCESS")
                print("Department count:", len(data.get("items", [])))
            else:
                print("ORDS request failed:", response.status_code)

        except httpx.RequestError as exc:
            print("ORDS NETWORK ERROR:", type(exc).__name__)

asyncio.run(main())
