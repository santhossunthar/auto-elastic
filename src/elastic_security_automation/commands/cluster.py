import argparse
from typing import Any

from elastic_security_automation.commands.common import (
    CommandContext,
    add_output_file_option,
    add_simple_option,
)


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "cluster",
        help="Summarize cluster health, indices, data streams, and storage.",
        description="Read cluster metadata and inventory from Elasticsearch.",
    )
    parser.add_argument(
        "--include-indices",
        action="store_true",
        help="include the full index inventory (the summary is always included)",
    )
    parser.add_argument(
        "--include-data-streams",
        action="store_true",
        help="include data-stream names and metadata",
    )
    add_output_file_option(parser)
    add_simple_option(parser)
    parser.set_defaults(handler=run)


def run(args: argparse.Namespace, context: CommandContext) -> dict[str, Any]:
    es = context.es()
    info = context.cluster_info()
    health = es.cluster_health()
    indices = es.indices()
    stats = es.cluster_stats()

    result: dict[str, Any] = {
        "cluster": {
            "name": info.get("cluster_name"),
            "version": info.get("version", {}).get("number"),
            "health": health.get("status"),
            "number_of_nodes": health.get("number_of_nodes"),
            "active_shards": health.get("active_shards"),
            "indices": len(indices),
            "store_size_bytes": stats.get("indices", {}).get("store", {}).get("size_in_bytes"),
        }
    }
    if args.include_indices or args.simple:
        result["indices"] = indices
    if args.include_data_streams:
        result["data_streams"] = es.data_streams().get("data_streams", [])
    return result


def simplify(result: dict[str, Any]) -> dict[str, Any]:
    cluster = result.get("cluster", {})
    indices = result.get("indices")
    return {
        "cluster": {"name": cluster.get("name")},
        "indices": sorted(
            str(index["index"])
            for index in indices or []
            if isinstance(index, dict) and index.get("index")
        )
        if indices is not None
        else None,
        "data_streams": sorted(
            str(stream["name"])
            for stream in result.get("data_streams", [])
            if isinstance(stream, dict) and stream.get("name")
        )
        if "data_streams" in result
        else None,
    }
