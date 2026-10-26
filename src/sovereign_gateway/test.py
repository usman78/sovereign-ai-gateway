
import asyncio
import os
import time
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv(Path.cwd() / ".env", override=True)

BASE_URL = os.getenv("ORDS_BASE_URL", "").rstrip("/")
CLIENT_ID = os.getenv("ORDS_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("ORDS_CLIENT_SECRET", "")

# Start with the same setting currently used by the gateway.
TRUST_ENV = os.getenv("ORDS_TEST_TRUST_ENV", "false").lower() == "true"


async def main():

    if not BASE_URL or not CLIENT_ID or not CLIENT_SECRET:
        print("CONFIGURATION ERROR: Missing ORDS settings in .env")
        return

    print("HTTPX version:", httpx.__version__)
    print("Proxy environment enabled:", TRUST_ENV)
    print("Testing OAuth authentication...")

    timeout = httpx.Timeout(
        connect=15.0,
        read=60.0,
        write=30.0,
        pool=10.0,
    )

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        trust_env=TRUST_ENV,
    ) as client:

        # Step 1: Obtain OAuth access token
        started = time.perf_counter()

        try:
            response = await client.post(
                f"{BASE_URL}/oauth/token",
                auth=(CLIENT_ID, CLIENT_SECRET),
                data={"grant_type": "client_credentials"},
                headers={"Accept": "application/json"},
            )

            elapsed = time.perf_counter() - started

            print("OAuth HTTP status:", response.status_code)
            print(f"OAuth elapsed: {elapsed:.2f} seconds")

            if response.status_code != 200:
                try:
                    error = response.json()
                    print("OAuth error:", error.get("error"))
                    print("Description:", error.get("error_description"))
                except ValueError:
                    print("Response was not valid JSON")
                return

            payload = response.json()
            token = payload.get("access_token")

            if not token:
                print("ERROR: OAuth response has no access_token")
                print("Response fields:", list(payload.keys()))
                return

            print("OAuth authentication: SUCCESS")
            print("Token type:", payload.get("token_type"))
            print("Token received: YES (value hidden)")

            # Step 2: Use token to access Oracle REST endpoint
            print("\nTesting departments endpoint...")

            started = time.perf_counter()

            result = await client.get(
                f"{BASE_URL}/ai-gateway/departments/",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
            )

            elapsed = time.perf_counter() - started

            print("ORDS HTTP status:", result.status_code)
            print(f"ORDS elapsed: {elapsed:.2f} seconds")

            if result.status_code == 200:
                data = result.json()
                print("ORDS connection: SUCCESS")
                print("Department count:", len(data.get("items", [])))
            else:
                print("ORDS request failed.")

        except httpx.ProxyError:
            print("PROXY ERROR: HTTPX could not connect through the configured proxy.")

        except httpx.TimeoutException as exc:
            print("TIMEOUT:", type(exc).__name__)

        except httpx.RequestError as exc:
            print("NETWORK ERROR:", type(exc).__name__)

        except Exception as exc:
            print("UNEXPECTED ERROR:", type(exc).__name__)


asyncio.run(main())
