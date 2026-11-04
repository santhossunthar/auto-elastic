import argparse
from typing import Any

from elastic_security_automation.commands.common import (
    CommandContext,
    add_output_file_option,
    add_simple_option,
)


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "data-views",
        help="List Kibana data views.",
        description="List data views available through the configured Kibana API.",
    )
    parser.add_argument(
        "--include-fields",
        action="store_true",
        help="fetch each data view's field metadata and runtime field definitions",
    )
    add_output_file_option(parser)
    add_simple_option(parser)
    parser.set_defaults(handler=run)


def run(args: argparse.Namespace, context: CommandContext) -> dict[str, Any]:
    views = context.kb().data_views()
    if not args.include_fields:
        return {"data_views": views}

    detailed: list[dict[str, Any]] = []
    for view in views:
        view_id = view.get("id")
        if not view_id:
            continue
        detailed.append(context.kb().data_view_fields(str(view_id)))
    return {"data_views": detailed}


def simplify(result: dict[str, Any]) -> dict[str, Any]:
    views = result.get("data_views", [])
    return {
        "data_views": [
            {
                "id": view.get("id"),
                "title": view.get("title"),
            }
            for view in views
            if isinstance(view, dict)
        ]
    }
