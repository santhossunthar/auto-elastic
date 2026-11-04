import json
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _records(value: Any, section: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"raw snapshot section {section!r} must be a JSON array")
    if not all(isinstance(item, dict) for item in value):
        raise ValueError(f"raw snapshot section {section!r} contains a non-object item")
    return value


def _field_summary(
    name: str,
    definition: Any,
    *,
    origin: str | None = None,
) -> dict[str, Any]:
    field = _as_dict(definition)
    summary: dict[str, Any] = {
        "name": field.get("name", name),
        "type": field.get("type", "unknown"),
    }
    for key in ("esTypes", "searchable", "aggregatable"):
        if key in field:
            summary[key] = field[key]
    if origin is not None:
        summary["origin"] = origin
    elif "origin" in field:
        summary["origin"] = field["origin"]
    if isinstance(field.get("script"), (str, dict)):
        summary["script"] = field["script"]
    return summary


def _view_fields(view: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    raw_fields = view.get("fields")
    raw_runtime = view.get("runtime_fields")
    if not isinstance(raw_runtime, dict):
        raw_runtime = view.get("runtimeFieldMap")
    runtime_definitions = dict(raw_runtime) if isinstance(raw_runtime, dict) else {}
    if isinstance(raw_fields, dict):
        runtime_definitions.update(
            {
                name: definition
                for name, definition in raw_fields.items()
                if _as_dict(definition).get("runtimeField", False)
            }
        )
    runtime_names = set(runtime_definitions)
    if isinstance(raw_fields, dict):
        mapped = [
            _field_summary(str(name), definition, origin="mapped")
            for name, definition in raw_fields.items()
            if name not in runtime_names
            and not _as_dict(definition).get("runtimeField", False)
        ]
    elif isinstance(raw_fields, list):
        mapped = [
            _field_summary(
                str(field.get("name", "")),
                field,
                origin=field.get("origin", "mapped"),
            )
            for field in raw_fields
            if isinstance(field, dict)
        ]
    else:
        mapped = []

    runtime = (
        [
            _field_summary(str(name), definition, origin="runtime")
            for name, definition in runtime_definitions.items()
        ]
        if runtime_definitions
        else []
    )
    return {"mapped": mapped, "runtime": runtime}


def _parse_cluster(data: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "cluster": _as_dict(data.get("cluster")),
        "indices": None,
        "data_streams": None,
    }
    if "indices" in data:
        raw_indices = _records(data["indices"], "indices")
        result["indices"] = [
            {
                "name": index.get("index"),
                "health": index.get("health"),
                "status": index.get("status"),
                "document_count": index.get(
                    "docs.count", _as_dict(index.get("docs")).get("count")
                ),
                "store_size": index.get(
                    "store.size", _as_dict(index.get("store")).get("size")
                ),
                "primary_shards": index.get("pri"),
                "replica_shards": index.get("rep"),
                "data_stream": index.get("data_stream"),
            }
            for index in raw_indices
        ]
    if "data_streams" in data:
        raw_streams = _records(data["data_streams"], "data_streams")
        result["data_streams"] = [
            {
                "name": stream.get("name"),
                "generation": stream.get("generation"),
                "status": stream.get("status"),
                "template": stream.get("template"),
                "ilm_policy": stream.get("ilm_policy"),
                "timestamp_field": _as_dict(stream.get("timestamp_field")).get("name"),
                "backing_indices": [
                    index.get("index_name")
                    for index in _records(stream.get("indices", []), "data_stream.indices")
                    if index.get("index_name")
                ],
            }
            for stream in raw_streams
        ]
    return result


def _parse_data_views(data: dict[str, Any]) -> dict[str, Any]:
    views: list[dict[str, Any]] = []
    for raw_view in _records(data.get("data_views", []), "data_views"):
        view = {
            "id": raw_view.get("id"),
            "title": raw_view.get("title"),
            "name": raw_view.get("name"),
            "namespaces": raw_view.get("namespaces"),
            "managed": raw_view.get("managed"),
            "time_field": raw_view.get("timeFieldName"),
        }
        fields = _view_fields(raw_view)
        view["mapped_fields"] = fields["mapped"] if "fields" in raw_view else None
        view["runtime_fields"] = (
            fields["runtime"]
            if "runtime_fields" in raw_view or "runtimeFieldMap" in raw_view
            else None
        )
        views.append(view)
    return {"data_views": views}


def _parse_fields(data: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"indices": None, "data_view": None}
    raw_indices = data.get("indices")
    if raw_indices is not None:
        if not isinstance(raw_indices, dict):
            raise ValueError("raw snapshot section 'indices' must be a JSON object")
        result["indices"] = {}
        for index_name, raw_index in raw_indices.items():
            index = _as_dict(raw_index)
            result["indices"][index_name] = {
                "mapped_fields": [
                    _field_summary(
                        str(field.get("name", "")), field, origin="mapped"
                    )
                    for field in _records(index.get("mapped_fields", []), "mapped_fields")
                ],
                "runtime_fields": [
                    _field_summary(
                        str(field.get("name", "")), field, origin="runtime"
                    )
                    for field in _records(index.get("runtime_fields", []), "runtime_fields")
                ],
            }

    raw_view = data.get("data_view")
    if isinstance(raw_view, dict):
        fields = _view_fields(raw_view)
        result["data_view"] = {
            "id": raw_view.get("id"),
            "title": raw_view.get("title"),
            "mapped_fields": fields["mapped"],
            "runtime_fields": fields["runtime"],
        }
    return result


def _parse_metrics(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "index": data.get("index"),
        "timestamp_field": data.get("timestamp_field"),
        "lookback": data.get("lookback"),
        "interval": data.get("interval"),
        "window_seconds": data.get("window_seconds"),
        "window_documents": data.get("window_documents"),
        "average_documents_per_second": data.get("average_documents_per_second"),
        "average_documents_per_minute": data.get("average_documents_per_minute"),
        "average_documents_per_hour": data.get("average_documents_per_hour"),
        "average_documents_per_day": data.get("average_documents_per_day"),
        "index_stats": _as_dict(data.get("index_stats")),
        "buckets": data.get("buckets"),
    }


def _parse_data_fields(data: dict[str, Any]) -> dict[str, Any]:
    views = _records(data.get("data_views", []), "data_views")
    parsed_views: list[dict[str, Any]] = []
    for view in views:
        groups = view.get("field_groups", {})
        if not isinstance(groups, dict):
            raise ValueError("data view field_groups must be a JSON object")
        parsed_views.append(
            {
                "id": view.get("id"),
                "title": view.get("title"),
                "time_field": view.get("time_field"),
                "sample_status": view.get("sample_status"),
                "sample_error": view.get("sample_error"),
                "sample_document_id": view.get("sample_document_id"),
                "field_count": view.get("field_count"),
                "field_groups": groups,
            }
        )
    return {
        "classification_note": data.get("classification_note"),
        "data_views": parsed_views,
    }


_COMMAND_PARSERS = {
    "cluster": _parse_cluster,
    "data-views": _parse_data_views,
    "data-fields": _parse_data_fields,
    "fields": _parse_fields,
    "metrics": _parse_metrics,
}


def parse_raw_snapshot(raw_path: Path) -> dict[str, Any]:
    with raw_path.open("r", encoding="utf-8") as raw_file:
        raw_snapshot = json.load(raw_file)
    if not isinstance(raw_snapshot, dict):
        raise ValueError(f"raw snapshot must contain a JSON object: {raw_path}")

    command = raw_snapshot.get("command")
    if not isinstance(command, str):
        raise ValueError("raw snapshot command must be a string")
    parser = _COMMAND_PARSERS.get(command)
    if parser is None:
        raise ValueError(f"unsupported raw snapshot command: {command!r}")

    data = raw_snapshot.get("data")
    if not isinstance(data, dict):
        raise ValueError(f"raw snapshot data must be a JSON object: {raw_path}")

    cluster = _as_dict(raw_snapshot.get("cluster"))
    raw_parents = raw_path.parents
    if len(raw_parents) < 3 or raw_parents[2].name != "raw":
        raise ValueError("raw snapshot must be located under outputs/raw/<cluster>/<date>")
    raw_relative_path = PurePosixPath(
        "raw",
        raw_path.parent.parent.name,
        raw_path.parent.name,
        raw_path.name,
    )
    return {
        "schema_version": "1.0",
        "document_type": "elastic_security_context",
        "collected_at": raw_snapshot.get("collected_at"),
        "cluster": {
            "name": cluster.get("name"),
            "uuid": cluster.get("uuid"),
            "version": cluster.get("version"),
        },
        "source": {
            "command": command,
            "arguments": _as_dict(raw_snapshot.get("arguments")),
            "raw_file": raw_path.name,
            "raw_path": str(raw_relative_path),
        },
        "security_context": parser(data),
    }
