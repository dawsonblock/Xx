from __future__ import annotations

from typing import Any

import httpx

from .config import BackendConfig


class BackendError(RuntimeError):
    pass


class SystemOneClient:
    """Connection-pooled client for all local/remote SystemOne backends."""

    def __init__(self, client: httpx.AsyncClient | None = None):
        self._client = client
        self._owns_client = client is None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient()
        return self._client

    def _headers(self, backend: BackendConfig) -> dict[str, str]:
        headers = {"content-type": "application/json"}
        if backend.api_key:
            headers["authorization"] = f"Bearer {backend.api_key}"
        return headers

    async def close(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def ask(self, backend: BackendConfig, payload: dict[str, Any]) -> dict[str, Any]:
        body = dict(payload)
        body["model"] = backend.model
        client = self._get_client()
        try:
            response = await client.post(backend.endpoint, json=body, headers=self._headers(backend), timeout=backend.timeout_s)
            if response.status_code >= 400:
                detail = response.text[:800]
                raise BackendError(f"{backend.name} returned HTTP {response.status_code}: {detail}")
            data = response.json()
            if not isinstance(data, dict) or not isinstance(data.get("answers"), dict):
                raise BackendError(f"{backend.name} returned an invalid SystemOne response")
            return data
        except BackendError:
            raise
        except (httpx.HTTPError, ValueError) as exc:
            raise BackendError(f"{backend.name} request failed: {exc}") from exc

    async def manifest(self, backend: BackendConfig) -> dict[str, Any]:
        client = self._get_client()
        url = backend.url.rstrip("/") + "/v1/fabric/manifest"
        try:
            response = await client.get(url, headers=self._headers(backend), timeout=min(backend.timeout_s, 5.0))
            if response.status_code >= 400:
                raise BackendError(f"{backend.name} manifest returned HTTP {response.status_code}")
            data = response.json()
            if not isinstance(data, dict):
                raise BackendError(f"{backend.name} manifest is not an object")
            return data
        except BackendError:
            raise
        except (httpx.HTTPError, ValueError) as exc:
            raise BackendError(f"{backend.name} manifest request failed: {exc}") from exc
