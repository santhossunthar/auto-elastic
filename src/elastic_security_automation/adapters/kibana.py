from typing import Any
from urllib.parse import quote

import httpx

from elastic_security_automation.config import Settings


class KibanaAdapter:
    """Adapter for Kibana data-view APIs, authenticated with the ES API key."""

    def __init__(self, client: httpx.Client) -> None:
        self._client = client

    @classmethod
    def from_settings(cls, settings: Settings) -> "KibanaAdapter":
        api_key = settings.require_api_key()
        client = httpx.Client(
            base_url=settings.require_kibana_url(),
            headers={
                "Authorization": f"ApiKey {api_key}",
                "kbn-xsrf": "elastic-security-automation",
            },
            timeout=settings.request_timeout,
            verify=settings.verify_certs,
        )
        return cls(client)

    def close(self) -> None:
        self._client.close()

    def data_views(self) -> list[dict[str, Any]]:
        response = self._client.get("/api/data_views")
        response.raise_for_status()
        payload = response.json()
        views = payload.get("data_view", [])
        if not isinstance(views, list):
            raise TypeError("Kibana returned an unexpected data-view response shape")
        return views

    def data_view(self, view_id: str) -> dict[str, Any]:
        response = self._client.get(
            f"/api/data_views/data_view/{quote(view_id, safe='')}"
        )
        response.raise_for_status()
        payload = response.json()
        view = payload.get("data_view")
        if not isinstance(view, dict):
            raise TypeError("Kibana returned an unexpected data-view response shape")
        return view

    def data_view_fields(self, view_id: str) -> dict[str, Any]:
        view = self.data_view(view_id)
        return {
            "id": view.get("id"),
            "title": view.get("title"),
            "time_field": view.get("timeFieldName"),
            "fields": view.get("fields", {}),
            "runtime_fields": view.get("runtimeFieldMap", {}),
        }
