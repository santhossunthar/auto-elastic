from collections.abc import Mapping, Sequence
from typing import Any

from elasticsearch import Elasticsearch

from elastic_security_automation.config import Settings


class ElasticsearchAdapter:
    """Adapter translating workflow operations to Elasticsearch API calls."""

    def __init__(self, client: Elasticsearch) -> None:
        self._client = client

    @classmethod
    def from_settings(cls, settings: Settings) -> "ElasticsearchAdapter":
        client = Elasticsearch(
            settings.elasticsearch_url,
            api_key=settings.require_api_key(),
            verify_certs=settings.verify_certs,
            request_timeout=settings.request_timeout,
        )
        return cls(client)

    def close(self) -> None:
        self._client.close()

    def cluster_info(self) -> dict[str, Any]:
        return self._body(self._client.info())

    def cluster_health(self) -> dict[str, Any]:
        return self._body(self._client.cluster.health())

    def indices(self) -> list[dict[str, Any]]:
        response = self._client.cat.indices(
            format="json", bytes="b", expand_wildcards="all"
        )
        body = getattr(response, "body", response)
        if not isinstance(body, list) or not all(isinstance(item, dict) for item in body):
            raise TypeError("Elasticsearch returned an unexpected index-list response shape")
        return body

    def data_streams(self) -> dict[str, Any]:
        return self._body(self._client.indices.get_data_stream(name="*"))

    def mappings(self, index: str) -> dict[str, Any]:
        return self._body(self._client.indices.get_mapping(index=index))

    def cluster_stats(self) -> dict[str, Any]:
        return self._body(self._client.cluster.stats())

    def index_stats(self, index: str) -> dict[str, Any]:
        return self._body(self._client.indices.stats(index=index))

    def sample_document_fields(
        self,
        index: str,
        field_names: Sequence[str],
        timestamp_field: str | None = None,
        runtime_mappings: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> dict[str, Any] | None:
        search_options: dict[str, Any] = {
            "index": index,
            "size": 1,
            "source": False,
            "fields": [{"field": field_name} for field_name in field_names],
            "track_total_hits": False,
        }
        if runtime_mappings:
            search_options["runtime_mappings"] = runtime_mappings
        if timestamp_field:
            search_options["sort"] = [
                {timestamp_field: {"order": "desc", "unmapped_type": "date"}}
            ]
        response = self._body(self._client.search(**search_options))
        hits = response.get("hits", {}).get("hits", [])
        if not hits:
            return None
        hit = hits[0]
        if not isinstance(hit, dict):
            raise TypeError("Elasticsearch returned an unexpected sample-document response")
        fields = hit.get("fields", {})
        if not isinstance(fields, dict):
            raise TypeError("Elasticsearch returned unexpected sample-document fields")
        return {"document_id": hit.get("_id"), "fields": fields}

    def document_histogram(
        self,
        index: str,
        timestamp_field: str,
        lookback: str,
        interval: str,
    ) -> dict[str, Any]:
        response = self._client.search(
            index=index,
            size=0,
            query={"range": {timestamp_field: {"gte": f"now-{lookback}", "lte": "now"}}},
            aggs={
                "documents_over_time": {
                    "date_histogram": {
                        "field": timestamp_field,
                        "fixed_interval": interval,
                        "min_doc_count": 0,
                    }
                }
            },
        )
        return self._body(response)

    @staticmethod
    def _body(response: Any) -> dict[str, Any]:
        body = getattr(response, "body", response)
        if not isinstance(body, dict):
            raise TypeError("Elasticsearch returned an unexpected response shape")
        return body
