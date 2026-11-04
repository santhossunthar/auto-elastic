import argparse
from typing import Any

from elastic_security_automation.commands.common import (
    CommandContext,
    add_output_file_option,
    add_simple_option,
    flatten_mapping,
    flatten_runtime_fields,
)


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "fields",
        help="Inspect index mappings and/or Kibana data-view fields.",
        description="Show mapped fields and optional Kibana runtime field metadata.",
    )
    parser.add_argument("--index", help="Elasticsearch index, alias, or wildcard pattern")
    parser.add_argument("--data-view-id", help="Kibana data-view ID")
    add_output_file_option(parser)
    add_simple_option(parser)
    parser.set_defaults(handler=run)


def run(args: argparse.Namespace, context: CommandContext) -> dict[str, Any]:
    if not args.index and not args.data_view_id:
        raise ValueError("provide at least one of --index or --data-view-id")

    result: dict[str, Any] = {}
    if args.index:
        mappings = context.es().mappings(args.index)
        result["indices"] = {}
        for index_name, index_data in mappings.items():
            mapping = index_data.get("mappings", {})
            result["indices"][index_name] = {
                "mapped_fields": flatten_mapping(mapping.get("properties", {})),
                "runtime_fields": flatten_runtime_fields(mapping.get("runtime", {})),
            }

    if args.data_view_id:
        view_data = context.kb().data_view_fields(args.data_view_id)
        result["data_view"] = {
            "id": view_data.get("id"),
            "title": view_data.get("title"),
            "fields": view_data.get("fields", {}),
            "runtime_fields": view_data.get("runtime_fields", {}),
        }
    return result


def simplify(result: dict[str, Any]) -> dict[str, Any]:
    simplified: dict[str, Any] = {}
    indices = result.get("indices")
    if isinstance(indices, dict):
        simplified["indices"] = {
            index_name: {
                "field_names": sorted(
                    {
                        str(field["name"])
                        for section in ("mapped_fields", "runtime_fields")
                        for field in index.get(section, [])
                        if isinstance(field, dict) and field.get("name")
                    }
                )
            }
            for index_name, index in indices.items()
            if isinstance(index, dict)
        }
    data_view = result.get("data_view")
    if isinstance(data_view, dict):
        fields = data_view.get("fields", {})
        runtime_fields = data_view.get("runtime_fields", {})
        simplified["data_view"] = {
            "id": data_view.get("id"),
            "title": data_view.get("title"),
            "field_names": sorted(
                {
                    str(name)
                    for name in [
                        *(fields.keys() if isinstance(fields, dict) else []),
                        *(
                            runtime_fields.keys()
                            if isinstance(runtime_fields, dict)
                            else []
                        ),
                    ]
                    if name != "_source"
                }
            ),
        }
    return simplified
