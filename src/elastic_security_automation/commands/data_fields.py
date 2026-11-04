import argparse
from html import escape
import json
from typing import Any

from elasticsearch import ApiError
from elastic_transport import TransportError

from elastic_security_automation.commands.common import (
    CommandContext,
    add_output_file_option,
    add_simple_option,
)

_COMMON_ROOTS = {
    "@timestamp",
    "agent",
    "client",
    "data_stream",
    "destination",
    "ecs",
    "error",
    "event",
    "host",
    "input",
    "labels",
    "log",
    "message",
    "observer",
    "organization",
    "related",
    "rule",
    "server",
    "source",
    "tags",
    "threat",
}
_PROTOCOL_ROOTS = {
    "dhcp",
    "dns",
    "email",
    "ftp",
    "http",
    "icmp",
    "imap",
    "kafka",
    "kerberos",
    "mongodb",
    "mqtt",
    "mysql",
    "network",
    "ntp",
    "postgresql",
    "pop3",
    "rpc",
    "smtp",
    "snmp",
    "ssh",
    "tls",
    "url",
    "websocket",
}
_SERVICE_ROOTS = {
    "application",
    "cloud",
    "container",
    "database",
    "file",
    "kubernetes",
    "orchestrator",
    "os",
    "package",
    "process",
    "registry",
    "redis",
    "service",
    "user",
}
_GROUPS = ("common", "protocols", "services", "custom_or_unclassified")


def _field_group(name: str) -> str:
    root = name.partition(".")[0].lower()
    if name.startswith(("custom.", "labels.")):
        return "custom_or_unclassified"
    if root in _COMMON_ROOTS:
        return "common"
    if root in _PROTOCOL_ROOTS:
        return "protocols"
    if root in _SERVICE_ROOTS:
        return "services"
    return "custom_or_unclassified"


def _field_custom_status(name: str, origin: str) -> str:
    if origin == "runtime":
        return "runtime_field"
    if name.startswith(("custom.", "labels.")):
        return "custom_namespace"
    return "unknown"


def _sample_value(sample_fields: dict[str, Any], name: str) -> tuple[bool, Any]:
    if name not in sample_fields:
        return False, None
    values = sample_fields[name]
    if isinstance(values, list):
        return bool(values), values[0] if values else None
    return True, values


def _field_record(
    name: str,
    definition: Any,
    sample_fields: dict[str, Any],
    runtime_names: set[str],
) -> dict[str, Any]:
    metadata = definition if isinstance(definition, dict) else {}
    origin = (
        "runtime"
        if name in runtime_names or metadata.get("runtimeField", False)
        else "mapped"
    )
    sample_available, sample_value = _sample_value(sample_fields, name)
    return {
        "name": name,
        "type": metadata.get("type", "unknown"),
        "group": _field_group(name),
        "field_origin": origin,
        "custom_status": _field_custom_status(name, origin),
        "searchable": metadata.get("searchable"),
        "aggregatable": metadata.get("aggregatable"),
        "sample_value": sample_value,
        "sample_available": sample_available,
    }


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "data-fields",
        help="Summarize data-view fields and sample values for security workflows.",
        description=(
            "Group data-view fields by common, protocol, service, or "
            "unclassified namespaces and retrieve one representative document."
        ),
    )
    parser.add_argument(
        "--data-view-id",
        help="inspect only this Kibana data-view ID (default: all data views)",
    )
    add_output_file_option(parser)
    add_simple_option(parser)
    parser.set_defaults(handler=run)


def run(args: argparse.Namespace, context: CommandContext) -> dict[str, Any]:
    kibana = context.kb()
    es = context.es()
    if args.data_view_id:
        views = [{"id": args.data_view_id}]
    else:
        views = kibana.data_views()

    data_views: list[dict[str, Any]] = []
    for listed_view in views:
        view_id = listed_view.get("id")
        if not view_id:
            continue
        view = kibana.data_view_fields(str(view_id))
        title = view.get("title")
        if not isinstance(title, str) or not title:
            data_views.append(
                {
                    "id": view_id,
                    "title": title,
                    "sample_status": "unavailable",
                    "sample_error": "data view has no usable index pattern",
                    "field_groups": {group: [] for group in _GROUPS},
                }
            )
            continue

        raw_fields = view.get("fields", {})
        if not isinstance(raw_fields, dict):
            raise TypeError(f"Kibana fields for data view {view_id!r} must be an object")
        runtime_fields = view.get("runtime_fields", {})
        if not isinstance(runtime_fields, dict):
            raise TypeError(
                f"Kibana runtime fields for data view {view_id!r} must be an object"
            )
        field_names = [
            name
            for name in dict.fromkeys([*raw_fields, *runtime_fields])
            if name != "_source"
        ]
        sample_document: dict[str, Any] | None = None
        sample_error: dict[str, Any] | None = None
        if args.simple:
            sample_status = "not_requested"
        else:
            try:
                timestamp_field = view.get("time_field")
                sample_document = es.sample_document_fields(
                    title,
                    field_names,
                    timestamp_field if isinstance(timestamp_field, str) else None,
                    runtime_fields,
                )
            except (ApiError, TransportError) as error:
                sample_error = {
                    "type": type(error).__name__,
                    "message": str(error),
                }
            sample_status = (
                "unavailable"
                if sample_error
                else "available"
                if sample_document is not None
                else "no_documents"
            )

        sample_fields = (
            sample_document.get("fields", {}) if sample_document is not None else {}
        )
        if not isinstance(sample_fields, dict):
            raise TypeError("sample document fields must be an object")

        runtime_names = set(runtime_fields)
        fields = [
            _field_record(str(name), definition, sample_fields, runtime_names)
            for name, definition in raw_fields.items()
            if name != "_source"
        ]
        for name, definition in runtime_fields.items():
            if name != "_source" and name not in raw_fields:
                fields.append(
                    _field_record(str(name), definition, sample_fields, runtime_names)
                )
        groups = {
            group: sorted(
                [field for field in fields if field["group"] == group],
                key=lambda field: field["name"],
            )
            for group in _GROUPS
        }

        view_result: dict[str, Any] = {
            "id": view.get("id", view_id),
            "title": title,
            "time_field": view.get("time_field"),
            "sample_status": sample_status,
            "sample_document_id": (
                sample_document.get("document_id")
                if sample_document is not None
                else None
            ),
            "field_count": len(fields),
            "field_groups": groups,
        }
        if sample_error is not None:
            view_result["sample_error"] = sample_error
        data_views.append(view_result)

    return {
        "classification_note": (
            "Groups are based on field-name namespaces. Mapped-field metadata does "
            "not identify whether a field was installed by an integration or added "
            "manually. Runtime fields and custom/labels namespaces are identified "
            "separately where the API or field name supports that distinction."
        ),
        "data_views": data_views,
    }


def simplify(result: dict[str, Any]) -> dict[str, Any]:
    views: list[dict[str, Any]] = []
    for view in result.get("data_views", []):
        if not isinstance(view, dict):
            continue
        groups = view.get("field_groups", {})
        views.append(
            {
                "id": view.get("id"),
                "title": view.get("title"),
                "sample_status": view.get("sample_status"),
                "field_groups": {
                    group: sorted(
                        str(field["name"])
                        for field in groups.get(group, [])
                        if isinstance(field, dict) and field.get("name")
                    )
                    for group in _GROUPS
                }
                if isinstance(groups, dict)
                else {group: [] for group in _GROUPS},
            }
        )
    return {
        "classification_note": result.get("classification_note"),
        "data_views": views,
    }


def render_markdown(summary: dict[str, Any]) -> str:
    context = summary.get("security_context", {})
    context = context if isinstance(context, dict) else {}
    lines = [
        "# Security Data Fields",
        "",
        f"Collected at: {summary.get('collected_at', 'unknown')}",
        "",
        str(context.get("classification_note", "")),
        "",
    ]
    views = context.get("data_views", [])
    for view in views:
        title = view.get("title") or view.get("id") or "Unknown data view"
        lines.extend(
            [
                f"## {escape(str(title))}",
                "",
                f"- Data-view ID: `{view.get('id')}`",
                f"- Time field: `{view.get('time_field')}`",
                f"- Sample status: `{view.get('sample_status')}`",
                f"- Sample document ID: `{view.get('sample_document_id')}`",
                "",
            ]
        )
        groups = view.get("field_groups", {})
        if not isinstance(groups, dict):
            continue
        for group in _GROUPS:
            lines.extend([f"### {group.replace('_', ' ').title()}", ""])
            fields = groups.get(group, [])
            if not fields:
                lines.extend(["_No fields._", ""])
                continue
            if all(isinstance(field, str) for field in fields):
                lines.extend(f"- `{escape(field)}`" for field in fields)
                lines.append("")
                continue
            lines.extend(
                [
                    "| Field | Type | Origin | Custom status | Sample value |",
                    "|---|---|---|---|---|",
                ]
            )
            for field in fields:
                sample = json.dumps(
                    field.get("sample_value"),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                sample = escape(sample, quote=False).replace("|", "\\|")
                sample = sample.replace("\r", " ").replace("\n", " ")
                if len(sample) > 180:
                    sample = f"{sample[:177]}..."
                lines.append(
                    "| "
                    + " | ".join(
                        str(field.get(key, ""))
                        .replace("&", "&amp;")
                        .replace("<", "&lt;")
                        .replace(">", "&gt;")
                        .replace("|", "\\|")
                        .replace("\r", " ")
                        .replace("\n", " ")
                        for key in ("name", "type", "field_origin", "custom_status")
                    )
                    + f" | {sample} |"
                )
            lines.append("")
    return "\n".join(lines)
