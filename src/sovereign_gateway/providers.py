
from __future__ import annotations

import logging
import httpx

logger = logging.getLogger(__name__)


class ProviderError(RuntimeError):
    pass


async def complete(
    provider: str,
    model: str,
    messages: list[dict[str, str]],
    ollama_base_url: str,
) -> str:

    if provider == "mock":
        return (
            f"Offline mock provider received {len(messages)} sanitized message(s). "
            "No external model was contacted."
        )

    if provider == "ollama":
        # Separate connection, response-reading and sending timeouts.
        timeout = httpx.Timeout(
            connect=5.0,
            read=300.0,
            write=30.0,
            pool=5.0,
        )

        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                # trust_env=False,  # Bypass system HTTP proxy settings.
            ) as client:

                logger.info(
                    "Sending request to Ollama: model=%s url=%s",
                    model,
                    ollama_base_url,
                )

                response = await client.post(
                    f"{ollama_base_url}/api/chat",
                    json={
                        "model": model,
                        "messages": messages,
                        "stream": False,
                    },
                )

                response.raise_for_status()

                payload = response.json()
                content = payload.get("message", {}).get("content")

                if not isinstance(content, str):
                    raise ProviderError(
                        "Ollama returned an unexpected response structure"
                    )

                logger.info("Ollama request completed successfully")
                return content

        except httpx.TimeoutException as exc:
            logger.exception("Ollama request timed out")
            raise ProviderError(
                f"Ollama request timed out: {type(exc).__name__}"
            ) from exc

        except httpx.HTTPStatusError as exc:
            logger.error(
                "Ollama HTTP error: status=%s body=%s",
                exc.response.status_code,
                exc.response.text[:500],
            )
            raise ProviderError(
                f"Ollama returned HTTP {exc.response.status_code}"
            ) from exc

        except httpx.RequestError as exc:
            logger.exception("Ollama connection error")
            raise ProviderError(
                f"Ollama connection failed: {type(exc).__name__}"
            ) from exc

        except (ValueError, KeyError, TypeError) as exc:
            logger.exception("Invalid Ollama response")
            raise ProviderError(
                "Ollama returned an invalid response"
            ) from exc

    raise ProviderError("Unsupported provider configured")
