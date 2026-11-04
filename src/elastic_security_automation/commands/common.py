import argparse
from dataclasses import dataclass
from typing import Any

from elastic_security_automation.adapters.elasticsearch import ElasticsearchAdapter
from elastic_security_automation.adapters.kibana import KibanaAdapter
from elastic_security_automation.config import Settings
from elastic_security_automation.events import EventBus


@dataclass
class CommandContext:
    settings: Settings
    events: EventBus
    elasticsearch: ElasticsearchAdapter | None = None
    kibana: KibanaAdapter | None = None
    _cluster_info_cache: dict[str, Any] | None = None

    def es(self) -> ElasticsearchAdapter:
        if self.elasticsearch is None:
            self.elasticsearch = ElasticsearchAdapter.from_settings(self.settings)
        return self.elasticsearch

    def kb(self) -> KibanaAdapter:
        if self.kibana is None:
            self.kibana = KibanaAdapter.from_settings(self.settings)
        return self.kibana

    def cluster_info(self) -> dict[str, Any]:
        if self._cluster_info_cache is None:
            self._cluster_info_cache = self.es().cluster_info()
        return self._cluster_info_cache

    def close(self) -> None:
        if self.elasticsearch is not None:
            self.elasticsearch.close()
        if self.kibana is not None:
            self.kibana.close()


def flatten_mapping(properties: dict[str, Any], prefix: str = "") -> list[dict[str, Any]]:
    fields: list[dict[str, Any]] = []
    for name, definition in properties.items():
        path = f"{prefix}.{name}" if prefix else name
        fields.append(
            {
                "name": path,
                "type": definition.get("type", "object"),
                "origin": "mapped",
            }
        )
        nested = definition.get("properties")
        if isinstance(nested, dict):
            fields.extend(flatten_mapping(nested, path))
        multifields = definition.get("fields")
        if isinstance(multifields, dict):
            fields.extend(flatten_mapping(multifields, path))
    return fields


def flatten_runtime_fields(runtime_fields: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "type": definition.get("type", "unknown"),
            "origin": "runtime",
        }
        for name, definition in runtime_fields.items()
    ]


def add_output_file_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--output-file",
        action="store_true",
        help="save raw, parsed, and latest summary files under outputs/",
    )


def add_simple_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--simple",
        action="store_true",
        help="return a concise list/summary instead of detailed records",
    )
