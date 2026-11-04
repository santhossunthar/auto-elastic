import argparse
import json
import sys
from collections.abc import Callable
from typing import Any

from pydantic import ValidationError

from elastic_security_automation.commands import (
    cluster,
    data_fields,
    data_views,
    fields,
    metrics,
)
from elastic_security_automation.commands.common import CommandContext
from elastic_security_automation.config import get_settings
from elastic_security_automation.events import EventBus, WorkflowEvent
from elastic_security_automation.outputs import (
    write_latest_summary,
    write_latest_markdown_summary,
    write_parsed_snapshot,
    write_snapshot,
)
from elastic_security_automation.parsing import parse_raw_snapshot

CommandHandler = Callable[[argparse.Namespace, CommandContext], dict[str, Any]]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="esa",
        description="Read-only Elastic discovery and metrics for security automation.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for module in (cluster, data_views, data_fields, fields, metrics):
        module.add_parser(subparsers)
    return parser


def _report_event(event: WorkflowEvent) -> None:
    if event.name == "command.failed":
        print(f"error: {event.payload['error']}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    context: CommandContext | None = None
    try:
        settings = get_settings()
        settings.configure_tls_warnings()
        context = CommandContext(settings=settings, events=EventBus())
        context.events.subscribe("command.failed", _report_event)
        context.events.publish(WorkflowEvent("command.started", {"command": args.command}))
        result = args.handler(args, context)
        output_result = result
        if args.simple:
            simplifier = {
                cluster.run: cluster.simplify,
                data_views.run: data_views.simplify,
                data_fields.run: data_fields.simplify,
                fields.run: fields.simplify,
                metrics.run: metrics.simplify,
            }[args.handler]
            output_result = simplifier(result)
        if args.output_file:
            cluster_info = context.cluster_info()
            arguments = {
                key: value
                for key, value in vars(args).items()
                if key not in {"handler", "output_file"}
            }
            output_path = write_snapshot(
                command=args.command,
                arguments=arguments,
                cluster_info=cluster_info,
                endpoint=settings.elasticsearch_url,
                data=result,
            )
            print(f"Snapshot written to {output_path}", file=sys.stderr)
            parsed_snapshot = parse_raw_snapshot(output_path)
            parsed_path = write_parsed_snapshot(
                raw_path=output_path,
                parsed_snapshot=parsed_snapshot,
            )
            print(f"Parsed snapshot written to {parsed_path}", file=sys.stderr)
            summary_document = parsed_snapshot
            if args.simple:
                summary_document = {
                    **parsed_snapshot,
                    "security_context": output_result,
                    "output_format": "simple",
                }
            summary_path = write_latest_summary(
                command=args.command,
                cluster_info=cluster_info,
                parsed_snapshot=summary_document,
                simple=args.simple,
            )
            print(f"Latest summary written to {summary_path}", file=sys.stderr)
            if args.command == "data-fields":
                markdown_path = write_latest_markdown_summary(
                    command="data-fields",
                    cluster_info=cluster_info,
                    content=data_fields.render_markdown(
                        summary_document
                    ),
                    simple=args.simple,
                )
                print(f"Field summary written to {markdown_path}", file=sys.stderr)
        context.events.publish(WorkflowEvent("command.completed", {"command": args.command}))
        print(json.dumps(output_result, indent=2, default=str))
        return 0
    except (ValidationError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except Exception as error:
        if context is not None:
            context.events.publish(
                WorkflowEvent("command.failed", {"command": args.command, "error": str(error)})
            )
        else:
            print(f"error: {error}", file=sys.stderr)
        return 1
    finally:
        if context is not None:
            context.close()
