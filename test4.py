
import asyncio
import os
import time
import httpx
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env", override=True)

BASE_URL = os.getenv("ORDS_BASE_URL", "").rstrip("/")
CLIENT_ID = os.getenv("ORDS_CLIENT_ID", "").strip()
CLIENT_SECRET = os.getenv("ORDS_CLIENT_SECRET", "").strip()

timeout = httpx.Timeout(
    connect=10,
    read=18,
    write=15,
    pool=10
)

TESTS = [
    (
        "User-Agent only",
        {
            "Accept": "application/json",
            "User-Agent": "PostmanRuntime/7.49.1"
        }
    ),
    (
        "Accept only",
        {
            "Accept": "*/*"
        }
    ),
    (
        "Custom application User-Agent",
        {
            "Accept": "application/json",
            "User-Agent": "SovereignAIGateway/0.1"
        }
    ),
    (
        "Both Postman-like headers",
        {
            "Accept": "*/*",
            "User-Agent": "PostmanRuntime/7.49.1"
        }
    ),
]


async def main():

    if not all([BASE_URL, CLIENT_ID, CLIENT_SECRET]):
        print("Missing ORDS configuration")
        return

    async with httpx.AsyncClient(
        timeout=timeout,
        trust_env=False,
        follow_redirects=False
    ) as client:

        for name, headers in TESTS:

            print(f"\n--- {name} ---")
            start = time.perf_counter()

            try:
                response = await client.post(
                    f"{BASE_URL}/oauth/token",
                    auth=(CLIENT_ID, CLIENT_SECRET),
                    data={"grant_type": "client_credentials"},
                    headers=headers
                )

                print("OAuth status:", response.status_code)
                print(f"Time: {time.perf_counter() - start:.2f}s")

                if response.status_code != 200:
                    print("OAuth request not successful")
                    continue

                token = response.json().get("access_token")

                if not token:
                    print("Access token missing")
                    continue

                print("OAuth authentication: SUCCESS")

                # Test the actual department endpoint with the same headers.
                api_headers = {
                    **headers,
                    "Authorization": f"Bearer {token}"
                }

                result = await client.get(
                    f"{BASE_URL}/ai-gateway/departments/",
                    headers=api_headers
                )

                print("Departments HTTP status:", result.status_code)

                if result.status_code == 200:
                    data = result.json()
                    print("Department count:", len(data.get("items", [])))

            except httpx.TimeoutException as exc:
                print("TIMEOUT:", type(exc).__name__)

            except httpx.RequestError as exc:
                print("NETWORK ERROR:", type(exc).__name__)

            except Exception as exc:
                print("ERROR:", type(exc).__name__)


asyncio.run(main())
