import argparse
import re
from typing import Any

from elastic_security_automation.commands.common import (
    CommandContext,
    add_output_file_option,
    add_simple_option,
)

_DURATION_RE = re.compile(r"^[1-9][0-9]*(?:s|m|h|d)$")
_INTERVAL_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "metrics",
        help="Summarize cluster/index metrics and timestamped document rates.",
        description="Estimate searchable document rates over a requested time window.",
    )
    parser.add_argument("--index", required=True, help="index, alias, or wildcard pattern")
    parser.add_argument(
        "--timestamp-field",
        default="@timestamp",
        help="date field used for the histogram (default: @timestamp)",
    )
    parser.add_argument(
        "--lookback",
        default="24h",
        help="time window, for example 30m, 24h, or 7d (default: 24h)",
    )
    parser.add_argument(
        "--interval",
        default="1h",
        help="histogram bucket width, for example 1m, 1h, or 1d (default: 1h)",
    )
    add_output_file_option(parser)
    add_simple_option(parser)
    parser.set_defaults(handler=run)


def _duration_seconds(duration: str, option: str) -> int:
    if not _DURATION_RE.fullmatch(duration):
        raise ValueError(f"--{option} must be a positive integer followed by s, m, h, or d")
    return int(duration[:-1]) * _INTERVAL_SECONDS[duration[-1]]


def run(args: argparse.Namespace, context: CommandContext) -> dict[str, Any]:
    lookback_seconds = _duration_seconds(args.lookback, "lookback")
    interval_seconds = _duration_seconds(args.interval, "interval")
    es = context.es()
    histogram = es.document_histogram(
        args.index, args.timestamp_field, args.lookback, args.interval
    )
    buckets = histogram.get("aggregations", {}).get("documents_over_time", {}).get("buckets", [])
    bucket_results = [
        {
            "key": bucket.get("key"),
            "key_as_string": bucket.get("key_as_string"),
            "documents": bucket.get("doc_count", 0),
            "documents_per_second": bucket.get("doc_count", 0) / interval_seconds,
        }
        for bucket in buckets
    ]
    document_count = sum(bucket["documents"] for bucket in bucket_results)
    stats = es.index_stats(args.index).get("indices", {})
    total_docs = sum(
        index_stats.get("total", {}).get("docs", {}).get("count", 0)
        for index_stats in stats.values()
    )
    total_store_bytes = sum(
        index_stats.get("total", {}).get("store", {}).get("size_in_bytes", 0)
        for index_stats in stats.values()
    )

    return {
        "index": args.index,
        "timestamp_field": args.timestamp_field,
        "lookback": args.lookback,
        "interval": args.interval,
        "window_seconds": lookback_seconds,
        "window_documents": document_count,
        "average_documents_per_second": document_count / lookback_seconds,
        "average_documents_per_minute": document_count * 60 / lookback_seconds,
        "average_documents_per_hour": document_count * 3600 / lookback_seconds,
        "average_documents_per_day": document_count * 86400 / lookback_seconds,
        "index_stats": {
            "document_count": total_docs,
            "store_size_bytes": total_store_bytes,
            "indices": list(stats),
        },
        "buckets": bucket_results,
    }


def simplify(result: dict[str, Any]) -> dict[str, Any]:
    index_stats = result.get("index_stats", {})
    return {
        "index": result.get("index"),
        "window_documents": result.get("window_documents"),
        "average_documents_per_second": result.get(
            "average_documents_per_second"
        ),
        "average_documents_per_minute": result.get(
            "average_documents_per_minute"
        ),
        "average_documents_per_hour": result.get("average_documents_per_hour"),
        "average_documents_per_day": result.get("average_documents_per_day"),
        "index_stats": {
            "document_count": index_stats.get("document_count"),
            "store_size_bytes": index_stats.get("store_size_bytes"),
        }
        if isinstance(index_stats, dict)
        else {},
    }
