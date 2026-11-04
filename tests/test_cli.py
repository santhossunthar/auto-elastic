from datetime import datetime, timedelta, timezone
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
from types import SimpleNamespace
import warnings

import pytest
import urllib3
from elastic_transport import SecurityWarning
from urllib3.exceptions import InsecureRequestWarning

from elastic_security_automation import cli
from elastic_security_automation.cli import _build_parser
from elastic_security_automation.adapters.elasticsearch import ElasticsearchAdapter
from elastic_security_automation.commands.cluster import simplify as simplify_cluster
from elastic_security_automation.commands.data_fields import render_markdown
from elastic_security_automation.commands.data_fields import simplify as simplify_data_fields
from elastic_security_automation.commands.data_fields import run as run_data_fields
from elastic_security_automation.commands.data_views import simplify as simplify_data_views
from elastic_security_automation.commands.fields import simplify as simplify_fields
from elastic_security_automation.commands.metrics import simplify as simplify_metrics
from elastic_security_automation.commands.common import (
    flatten_mapping,
    flatten_runtime_fields,
)
from elastic_security_automation.commands.metrics import _duration_seconds
from elastic_security_automation.config import Settings
from elastic_security_automation.events import EventBus, WorkflowEvent
from elastic_security_automation.outputs import (
    project_root,
    write_latest_markdown_summary,
    write_latest_summary,
    write_parsed_snapshot,
    write_snapshot,
)
from elastic_security_automation.parsing import parse_raw_snapshot


def test_top_level_help_lists_command_modules(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as result:
        _build_parser().parse_args(["--help"])

    assert result.value.code == 0
    output = capsys.readouterr().out
    assert "cluster" in output
    assert "data-views" in output
    assert "fields" in output
    assert "metrics" in output
    assert "data-fields" in output


def test_module_help_lists_module_arguments(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as result:
        _build_parser().parse_args(["metrics", "--help"])

    assert result.value.code == 0
    output = capsys.readouterr().out
    assert "--timestamp-field" in output
    assert "--lookback" in output
    assert "--interval" in output


def test_module_simplifiers_keep_only_summary_values() -> None:
    assert simplify_cluster(
        {
            "cluster": {"name": "elastic", "health": "yellow"},
            "indices": [{"index": "logs-b"}, {"index": "logs-a"}],
            "data_streams": [{"name": "logs-events"}],
        }
    ) == {
        "cluster": {"name": "elastic"},
        "indices": ["logs-a", "logs-b"],
        "data_streams": ["logs-events"],
    }
    assert simplify_data_views(
        {
            "data_views": [
                {"id": "view-1", "title": "logs-*", "fields": {"message": {}}}
            ]
        }
    ) == {"data_views": [{"id": "view-1", "title": "logs-*"}]}
    assert simplify_fields(
        {
            "indices": {
                "logs-a": {
                    "mapped_fields": [{"name": "message"}, {"name": "@timestamp"}],
                    "runtime_fields": [{"name": "event.risk_score"}],
                }
            },
            "data_view": {
                "id": "view-1",
                "title": "logs-*",
                "fields": {"message": {}, "_source": {}},
                "runtime_fields": {"event.risk_score": {}},
            },
        }
    ) == {
        "indices": {
            "logs-a": {
                "field_names": ["@timestamp", "event.risk_score", "message"]
            }
        },
        "data_view": {
            "id": "view-1",
            "title": "logs-*",
            "field_names": ["event.risk_score", "message"],
        },
    }
    assert simplify_metrics(
        {
            "index": "logs-*",
            "window_documents": 7,
            "buckets": [{"documents": 3}],
            "index_stats": {
                "document_count": 10,
                "store_size_bytes": 100,
                "indices": ["logs-a"],
            },
        }
    ) == {
        "index": "logs-*",
        "window_documents": 7,
        "average_documents_per_second": None,
        "average_documents_per_minute": None,
        "average_documents_per_hour": None,
        "average_documents_per_day": None,
        "index_stats": {"document_count": 10, "store_size_bytes": 100},
    }
    assert simplify_data_fields(
        {
            "classification_note": "Grouped by namespace.",
            "data_views": [
                {
                    "id": "view-1",
                    "title": "logs-*",
                    "sample_status": "available",
                    "sample_document_id": "doc-1",
                    "field_groups": {
                        "common": [{"name": "message", "sample_value": "secret"}],
                        "protocols": [],
                        "services": [],
                        "custom_or_unclassified": [],
                    },
                }
            ],
        }
    ) == {
        "classification_note": "Grouped by namespace.",
        "data_views": [
            {
                "id": "view-1",
                "title": "logs-*",
                "sample_status": "available",
                "field_groups": {
                    "common": ["message"],
                    "protocols": [],
                    "services": [],
                    "custom_or_unclassified": [],
                },
            }
        ],
    }


def test_simple_cli_writes_compact_summary_and_keeps_raw_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: dict[str, object] = {}

    class FakeSettings:
        elasticsearch_url = "https://elastic.example:9200"

        def configure_tls_warnings(self) -> None:
            return None

    class FakeKibana:
        def data_views(self) -> list[dict[str, object]]:
            return [
                {
                    "id": "view-1",
                    "title": "logs-*",
                    "namespaces": ["default"],
                    "timeFieldName": "@timestamp",
                }
            ]

    class FakeContext:
        def __init__(self) -> None:
            self.events = EventBus()

        def kb(self) -> FakeKibana:
            return FakeKibana()

        def cluster_info(self) -> dict[str, str]:
            return {"cluster_name": "elastic", "cluster_uuid": "cluster-1"}

        def close(self) -> None:
            return None

    monkeypatch.setattr(cli, "get_settings", FakeSettings)
    monkeypatch.setattr(cli, "CommandContext", lambda settings, events: FakeContext())

    def capture_raw(**kwargs: object) -> Path:
        captured["raw_data"] = kwargs["data"]
        return tmp_path / "raw.json"

    def capture_summary(**kwargs: object) -> Path:
        captured["summary"] = kwargs["parsed_snapshot"]
        return tmp_path / "summary.json"

    monkeypatch.setattr(cli, "write_snapshot", capture_raw)
    monkeypatch.setattr(
        cli,
        "parse_raw_snapshot",
        lambda path: {
            "schema_version": "1.0",
            "security_context": {"data_views": [{"id": "view-1", "title": "logs-*"}]},
        },
    )
    monkeypatch.setattr(
        cli,
        "write_parsed_snapshot",
        lambda raw_path, parsed_snapshot: tmp_path / "parsed.json",
    )
    monkeypatch.setattr(cli, "write_latest_summary", capture_summary)

    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        exit_code = cli.main(["data-views", "--simple", "--output-file"])

    output = json.loads(stdout.getvalue())
    raw_data = captured["raw_data"]
    summary = captured["summary"]

    assert exit_code == 0
    assert output == {"data_views": [{"id": "view-1", "title": "logs-*"}]}
    assert raw_data["data_views"][0]["namespaces"] == ["default"]
    assert summary["output_format"] == "simple"
    assert summary["security_context"] == output


@pytest.mark.parametrize(
    "arguments",
    [
        ["cluster", "--output-file"],
        ["data-views", "--output-file"],
        ["fields", "--output-file"],
        ["metrics", "--index", "logs-*", "--output-file"],
        ["cluster", "--simple"],
        ["data-views", "--simple"],
        ["fields", "--simple", "--index", "logs-*"],
        ["data-fields", "--simple"],
        ["metrics", "--index", "logs-*", "--simple"],
    ],
)
def test_each_module_accepts_output_file_flag(arguments: list[str]) -> None:
    parsed = _build_parser().parse_args(arguments)

    assert parsed.simple is ("--simple" in arguments)
    assert parsed.output_file is ("--output-file" in arguments)


def test_snapshot_is_structured_cluster_scoped_and_never_overwritten(
    tmp_path: Path,
) -> None:
    timestamp = datetime(
        2026, 11, 4, 12, 12, 13, tzinfo=timezone(timedelta(hours=5, minutes=30))
    )
    cluster_info = {
        "cluster_name": "elastic / prod",
        "cluster_uuid": "cluster-uuid-1",
        "version": {"number": "9.2.4"},
    }

    first_path = write_snapshot(
        command="cluster",
        arguments={"include_indices": True},
        cluster_info=cluster_info,
        endpoint="https://user:password@elastic.example:9200/",
        data={"health": "green"},
        output_root=tmp_path,
        collected_at=timestamp,
    )
    first_snapshot = json.loads(first_path.read_text(encoding="utf-8"))
    second_path = write_snapshot(
        command="cluster",
        arguments={"include_indices": True},
        cluster_info=cluster_info,
        endpoint="https://user:password@elastic.example:9200/",
        data={"health": "yellow"},
        output_root=tmp_path,
        collected_at=timestamp,
    )

    assert first_path == (
        tmp_path
        / "outputs"
        / "raw"
        / "elastic_prod_cluster-uuid-1"
        / "2026-11-04"
        / "20261104T064213.000000Z__cluster__include-indices.json"
    )
    assert second_path.name == (
        "20261104T064213.000000Z__cluster__include-indices_02.json"
    )
    assert first_snapshot["schema_version"] == "1.0"
    assert first_snapshot["collected_at"] == "2026-11-04T12:12:13.000000+05:30"
    assert first_snapshot["cluster"]["endpoint"] == {
        "scheme": "https",
        "host": "elastic.example",
        "port": 9200,
    }
    assert first_snapshot["data"] == {"health": "green"}


def test_snapshot_filename_distinguishes_command_options_and_parameters(
    tmp_path: Path,
) -> None:
    cluster_info = {
        "cluster_name": "elastic",
        "cluster_uuid": "cluster-1",
        "version": {"number": "9.2.4"},
    }
    timestamp = datetime(
        2026, 11, 4, 12, 12, 14, tzinfo=timezone(timedelta(hours=5, minutes=30))
    )
    snapshots = [
        (
            "cluster",
            {"include_indices": True, "include_data_streams": True},
            "20261104T064214.000000Z__cluster__include-data-streams__include-indices.json",
        ),
        (
            "data-views",
            {"include_fields": True},
            "20261104T064214.000000Z__data-views__include-fields.json",
        ),
        (
            "metrics",
            {"index": "logs-*", "lookback": "24h"},
            "20261104T064214.000000Z__metrics__index-logs-all__lookback-24h.json",
        ),
    ]

    for command, arguments, expected_name in snapshots:
        output_path = write_snapshot(
            command=command,
            arguments=arguments,
            cluster_info=cluster_info,
            endpoint="https://elastic.example:9200",
            data={},
            output_root=tmp_path,
            collected_at=timestamp,
        )
        assert output_path.name == expected_name


def test_snapshot_filename_bounds_long_argument_names(tmp_path: Path) -> None:
    output_path = write_snapshot(
        command="fields",
        arguments={"index": "logs-" + "x" * 300, "data_view_id": "view-" + "y" * 300},
        cluster_info={"cluster_name": "elastic", "cluster_uuid": "cluster-1"},
        endpoint="https://elastic.example:9200",
        data={},
        output_root=tmp_path,
        collected_at=datetime(
            2026, 11, 4, 12, 12, 15, tzinfo=timezone(timedelta(hours=5, minutes=30))
        ),
    )

    assert len(output_path.name) <= 140


def test_snapshot_root_does_not_depend_on_invocation_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected_root = project_root()
    monkeypatch.chdir(tmp_path)

    assert project_root() == expected_root


def test_raw_snapshot_is_parsed_to_paired_security_context_file(tmp_path: Path) -> None:
    cluster_info = {
        "cluster_name": "elastic",
        "cluster_uuid": "cluster-1",
        "version": {"number": "9.2.4"},
    }
    raw_path = write_snapshot(
        command="cluster",
        arguments={"include_indices": True, "include_data_streams": True},
        cluster_info=cluster_info,
        endpoint="https://elastic.example:9200",
        data={
            "cluster": {
                "health": "yellow",
                "number_of_nodes": 1,
                "active_shards": 4,
            },
            "indices": [
                {
                    "index": "logs-endpoint.events",
                    "health": "yellow",
                    "status": "open",
                    "docs.count": "42",
                    "store.size": "8kb",
                    "pri": "1",
                    "rep": "1",
                }
            ],
            "data_streams": [
                {
                    "name": "logs-endpoint.events-default",
                    "generation": 3,
                    "timestamp_field": {"name": "@timestamp"},
                    "indices": [{"index_name": ".ds-logs-endpoint.events-default-000003"}],
                }
            ],
        },
        output_root=tmp_path,
        collected_at=datetime(
            2026, 11, 4, 12, 12, 13, tzinfo=timezone(timedelta(hours=5, minutes=30))
        ),
    )

    parsed_document = parse_raw_snapshot(raw_path)
    parsed_path = write_parsed_snapshot(
        raw_path=raw_path,
        parsed_snapshot=parsed_document,
        output_root=tmp_path,
    )
    parsed = json.loads(parsed_path.read_text(encoding="utf-8"))

    assert raw_path.parent == (
        tmp_path
        / "outputs"
        / "raw"
        / "elastic_cluster-1"
        / "2026-11-04"
    )
    assert parsed_path == (
        tmp_path
        / "outputs"
        / "parsed"
        / "elastic_cluster-1"
        / "2026-11-04"
        / raw_path.name
    )
    assert parsed["document_type"] == "elastic_security_context"
    assert parsed["source"]["raw_file"] == raw_path.name
    assert parsed["security_context"]["indices"][0] == {
        "name": "logs-endpoint.events",
        "health": "yellow",
        "status": "open",
        "document_count": "42",
        "store_size": "8kb",
        "primary_shards": "1",
        "replica_shards": "1",
        "data_stream": None,
    }
    assert parsed["security_context"]["data_streams"][0]["timestamp_field"] == "@timestamp"


def test_latest_summary_is_cluster_and_module_scoped_and_overwritten(
    tmp_path: Path,
) -> None:
    cluster_info = {
        "cluster_name": "elastic",
        "cluster_uuid": "cluster-1",
        "version": {"number": "9.2.4"},
    }
    summary_path = write_latest_summary(
        command="cluster",
        cluster_info=cluster_info,
        parsed_snapshot={"collected_at": "first", "security_context": {"health": "yellow"}},
        output_root=tmp_path,
    )
    second_path = write_latest_summary(
        command="cluster",
        cluster_info=cluster_info,
        parsed_snapshot={"collected_at": "second", "security_context": {"health": "green"}},
        output_root=tmp_path,
    )
    other_module_path = write_latest_summary(
        command="data-views",
        cluster_info=cluster_info,
        parsed_snapshot={"security_context": {"data_views": []}},
        output_root=tmp_path,
    )
    summary = json.loads(summary_path.read_text(encoding="utf-8"))

    assert summary_path == (
        tmp_path / "outputs" / "summary" / "elastic_cluster-1" / "cluster.json"
    )
    assert second_path == summary_path
    assert summary["collected_at"] == "second"
    assert other_module_path.name == "data-views.json"
    assert other_module_path.parent == summary_path.parent
    assert list(summary_path.parent.glob("*.tmp")) == []


def test_simple_latest_summary_does_not_overwrite_detailed_summary(
    tmp_path: Path,
) -> None:
    cluster_info = {"cluster_name": "elastic", "cluster_uuid": "cluster-1"}
    detailed = {"output_format": "detailed", "security_context": {"fields": ["a", "b"]}}
    simple = {"output_format": "simple", "security_context": {"fields": ["a"]}}

    detailed_path = write_latest_summary(
        command="data-views",
        cluster_info=cluster_info,
        parsed_snapshot=detailed,
        output_root=tmp_path,
    )
    simple_path = write_latest_summary(
        command="data-views",
        cluster_info=cluster_info,
        parsed_snapshot=simple,
        simple=True,
        output_root=tmp_path,
    )
    write_latest_summary(
        command="data-views",
        cluster_info=cluster_info,
        parsed_snapshot={**simple, "security_context": {"fields": ["a", "c"]}},
        simple=True,
        output_root=tmp_path,
    )

    assert detailed_path.name == "data-views.json"
    assert simple_path.name == "data-views-simple.json"
    assert json.loads(detailed_path.read_text(encoding="utf-8")) == detailed
    assert json.loads(simple_path.read_text(encoding="utf-8"))["security_context"] == {
        "fields": ["a", "c"]
    }


def test_data_fields_command_groups_fields_and_adds_sample_values() -> None:
    class FakeKibana:
        def data_views(self) -> list[dict[str, str]]:
            return [{"id": "view-1"}]

        def data_view_fields(self, view_id: str) -> dict[str, object]:
            assert view_id == "view-1"
            return {
                "id": view_id,
                "title": "logs-*",
                "time_field": "@timestamp",
                "fields": {
                    "_source": {"type": "_source"},
                    "@timestamp": {"type": "date"},
                    "dns.question.name": {"type": "keyword"},
                    "process.name": {"type": "keyword"},
                    "custom.alert_context": {"type": "keyword"},
                    "labels.owner": {"type": "keyword"},
                    "event.risk_score": {"type": "long", "runtimeField": True},
                },
                "runtime_fields": {
                    "event.risk_score": {"type": "long"},
                },
            }

    class FakeElasticsearch:
        def sample_document_fields(
            self,
            index: str,
            field_names: list[str],
            timestamp_field: str | None,
            runtime_mappings: dict[str, object],
        ) -> dict[str, object]:
            assert index == "logs-*"
            assert "_source" not in field_names
            assert "@timestamp" in field_names
            assert "event.risk_score" in field_names
            assert timestamp_field == "@timestamp"
            assert "event.risk_score" in runtime_mappings
            return {
                "document_id": "doc-1",
                "fields": {
                    "@timestamp": ["2026-11-04T10:00:00Z"],
                    "dns.question.name": ["example.org"],
                    "process.name": ["browser.exe"],
                    "custom.alert_context": ["suspicious"],
                    "labels.owner": ["security"],
                    "event.risk_score": [72],
                },
            }

    context = SimpleNamespace(kb=lambda: FakeKibana(), es=lambda: FakeElasticsearch())
    args = SimpleNamespace(data_view_id=None, simple=False)

    result = run_data_fields(args, context)
    view = result["data_views"][0]
    groups = view["field_groups"]

    assert view["sample_status"] == "available"
    assert view["sample_document_id"] == "doc-1"
    assert groups["common"][0]["sample_value"] == "2026-11-04T10:00:00Z"
    assert groups["protocols"][0]["name"] == "dns.question.name"
    assert groups["protocols"][0]["sample_value"] == "example.org"
    assert groups["services"][0]["name"] == "process.name"
    custom_fields = groups["custom_or_unclassified"]
    assert [field["name"] for field in custom_fields] == [
        "custom.alert_context",
        "labels.owner",
    ]
    runtime_field = next(field for field in groups["common"] if field["name"] == "event.risk_score")
    assert runtime_field["field_origin"] == "runtime"
    assert runtime_field["sample_value"] == 72


def test_data_fields_are_supported_in_raw_and_parsed_snapshots(tmp_path: Path) -> None:
    raw_path = (
        tmp_path
        / "outputs"
        / "raw"
        / "elastic_cluster-1"
        / "2026-11-04"
        / "data-fields.json"
    )
    raw_path.parent.mkdir(parents=True)
    raw_path.write_text(
        json.dumps(
            {
                "command": "data-fields",
                "collected_at": "2026-11-04T12:00:00+05:30",
                "cluster": {"name": "elastic", "uuid": "cluster-1"},
                "arguments": {},
                "data": {
                    "classification_note": "Grouped by namespace.",
                    "data_views": [
                        {
                            "id": "view-1",
                            "title": "logs-*",
                            "field_count": 1,
                            "sample_status": "available",
                            "field_groups": {
                                "common": [
                                    {
                                        "name": "message",
                                        "type": "text",
                                        "group": "common",
                                        "field_origin": "mapped",
                                        "custom_status": "unknown",
                                        "sample_value": "example",
                                        "sample_available": True,
                                    }
                                ],
                                "protocols": [],
                                "services": [],
                                "custom_or_unclassified": [],
                            },
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )

    parsed = parse_raw_snapshot(raw_path)

    assert parsed["security_context"]["data_views"][0]["field_groups"]["common"][0][
        "sample_value"
    ] == "example"


def test_sample_document_adapter_requests_fields_without_full_source() -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.options: dict[str, object] = {}

        def search(self, **options: object) -> dict[str, object]:
            self.options = options
            return {
                "hits": {
                    "hits": [
                        {
                            "_id": "doc-1",
                            "fields": {"message": ["sample"]},
                        }
                    ]
                }
            }

    client = FakeClient()
    adapter = ElasticsearchAdapter(client)  # type: ignore[arg-type]

    sample = adapter.sample_document_fields(
        "logs-*",
        ["message", "event.risk_score"],
        "@timestamp",
        {"event.risk_score": {"type": "long"}},
    )

    assert sample == {"document_id": "doc-1", "fields": {"message": ["sample"]}}
    assert client.options["source"] is False
    assert client.options["fields"] == [{"field": "message"}, {"field": "event.risk_score"}]
    assert client.options["runtime_mappings"] == {
        "event.risk_score": {"type": "long"}
    }
    assert client.options["sort"] == [
        {"@timestamp": {"order": "desc", "unmapped_type": "date"}}
    ]


def test_kibana_data_view_metadata_includes_time_field() -> None:
    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {
                "data_view": {
                    "id": "view-1",
                    "title": "logs-*",
                    "timeFieldName": "@timestamp",
                    "fields": {"message": {"type": "text"}},
                    "runtimeFieldMap": {},
                }
            }

    class FakeClient:
        def get(self, path: str) -> FakeResponse:
            assert path == "/api/data_views/data_view/view-1"
            return FakeResponse()

    from elastic_security_automation.adapters.kibana import KibanaAdapter

    view = KibanaAdapter(FakeClient()).data_view_fields("view-1")  # type: ignore[arg-type]

    assert view["time_field"] == "@timestamp"


def test_data_fields_mark_unavailable_sample_values() -> None:
    class FakeKibana:
        def data_views(self) -> list[dict[str, str]]:
            return [{"id": "view-1"}]

        def data_view_fields(self, view_id: str) -> dict[str, object]:
            return {
                "id": view_id,
                "title": "logs-empty-*",
                "fields": {"message": {"type": "text"}},
                "runtime_fields": {},
            }

    class FakeElasticsearch:
        def sample_document_fields(
            self,
            index: str,
            field_names: list[str],
            timestamp_field: str | None,
            runtime_mappings: dict[str, object],
        ) -> None:
            return None

    context = SimpleNamespace(kb=lambda: FakeKibana(), es=lambda: FakeElasticsearch())
    result = run_data_fields(SimpleNamespace(data_view_id=None, simple=False), context)
    view = result["data_views"][0]
    message_field = view["field_groups"]["common"][0]

    assert view["sample_status"] == "no_documents"
    assert message_field["sample_available"] is False
    assert message_field["sample_value"] is None


def test_data_fields_markdown_and_file_are_written_as_latest_pair(
    tmp_path: Path,
) -> None:
    summary = {
        "collected_at": "2026-11-04T12:00:00+05:30",
        "security_context": {
            "classification_note": "Fields are grouped by namespace.",
            "data_views": [
                {
                    "id": "view-1",
                    "title": "logs-*",
                    "time_field": "@timestamp",
                    "sample_status": "available",
                    "sample_document_id": "doc-1",
                    "field_groups": {
                        "common": [
                            {
                                "name": "message",
                                "type": "text",
                                "field_origin": "mapped",
                                "custom_status": "unknown",
                                "sample_value": "example | event",
                            }
                        ],
                        "protocols": [],
                        "services": [],
                        "custom_or_unclassified": [],
                    },
                }
            ],
        },
    }
    cluster_info = {"cluster_name": "elastic", "cluster_uuid": "cluster-1"}
    json_path = write_latest_summary(
        command="data-fields",
        cluster_info=cluster_info,
        parsed_snapshot=summary,
        output_root=tmp_path,
    )
    markdown_path = write_latest_markdown_summary(
        command="data-fields",
        cluster_info=cluster_info,
        content=render_markdown(summary),
        output_root=tmp_path,
    )
    markdown = markdown_path.read_text(encoding="utf-8")

    assert json_path.name == "data-fields.json"
    assert markdown_path.name == "data-fields.md"
    assert "| message | text | mapped | unknown | \"example \\| event\" |" in markdown


def test_simple_data_fields_markdown_has_separate_latest_filename(tmp_path: Path) -> None:
    cluster_info = {"cluster_name": "elastic", "cluster_uuid": "cluster-1"}
    detailed_path = write_latest_markdown_summary(
        command="data-fields",
        cluster_info=cluster_info,
        content="# Detailed",
        output_root=tmp_path,
    )
    simple_path = write_latest_markdown_summary(
        command="data-fields",
        cluster_info=cluster_info,
        content="# Simple",
        simple=True,
        output_root=tmp_path,
    )

    assert detailed_path.name == "data-fields.md"
    assert simple_path.name == "data-fields-simple.md"
    assert detailed_path.read_text(encoding="utf-8") == "# Detailed\n"
    assert simple_path.read_text(encoding="utf-8") == "# Simple\n"


def test_data_fields_simple_markdown_lists_names_without_values() -> None:
    markdown = render_markdown(
        {
            "security_context": {
                "classification_note": "Grouped by namespace.",
                "data_views": [
                    {
                        "id": "view-1",
                        "title": "logs-*",
                        "time_field": "@timestamp",
                        "sample_status": "not_requested",
                        "sample_document_id": None,
                        "field_groups": {
                            "common": ["message", "@timestamp"],
                            "protocols": ["dns.question.name"],
                            "services": [],
                            "custom_or_unclassified": [],
                        },
                    }
                ],
            }
        }
    )

    assert "- `message`" in markdown
    assert "- `dns.question.name`" in markdown
    assert "Sample value" not in markdown
    assert "example" not in markdown


def test_data_view_parser_extracts_security_relevant_field_metadata(tmp_path: Path) -> None:
    raw_path = (
        tmp_path
        / "outputs"
        / "raw"
        / "elastic_cluster-1"
        / "2026-11-04"
        / "data-views.json"
    )
    raw_path.parent.mkdir(parents=True)
    raw_path.write_text(
        json.dumps(
            {
                "command": "data-views",
                "collected_at": "2026-11-04T12:00:00+05:30",
                "cluster": {"name": "elastic", "uuid": "cluster-1"},
                "arguments": {"include_fields": True},
                "data": {
                    "data_views": [
                        {
                            "id": "view-1",
                            "title": "logs-*",
                            "timeFieldName": "@timestamp",
                            "fields": {
                                "@timestamp": {
                                    "name": "@timestamp",
                                    "type": "date",
                                    "searchable": True,
                                    "aggregatable": True,
                                }
                            },
                            "runtime_fields": {
                                "event.risk_score": {
                                    "type": "long",
                                    "script": {"source": "emit(50)"},
                                }
                            },
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    parsed = parse_raw_snapshot(raw_path)
    view = parsed["security_context"]["data_views"][0]

    assert view["mapped_fields"] == [
        {
            "name": "@timestamp",
            "type": "date",
            "searchable": True,
            "aggregatable": True,
            "origin": "mapped",
        }
    ]
    assert view["runtime_fields"][0] == {
        "name": "event.risk_score",
        "type": "long",
        "origin": "runtime",
        "script": {"source": "emit(50)"},
    }
    assert parsed["source"]["raw_path"] == (
        "raw/elastic_cluster-1/2026-11-04/data-views.json"
    )


@pytest.mark.parametrize(
    ("command", "data", "expected_context"),
    [
        (
            "fields",
            {
                "indices": {
                    "logs-endpoint.events": {
                        "mapped_fields": [
                            {"name": "@timestamp", "type": "date", "origin": "mapped"}
                        ],
                        "runtime_fields": [
                            {"name": "event.risk_score", "type": "long", "origin": "runtime"}
                        ],
                    }
                },
                "data_view": None,
            },
            {
                "indices": {
                    "logs-endpoint.events": {
                        "mapped_fields": [
                            {"name": "@timestamp", "type": "date", "origin": "mapped"}
                        ],
                        "runtime_fields": [
                            {"name": "event.risk_score", "type": "long", "origin": "runtime"}
                        ],
                    }
                },
                "data_view": None,
            },
        ),
        (
            "metrics",
            {
                "index": "logs-*",
                "timestamp_field": "@timestamp",
                "lookback": "24h",
                "interval": None,
                "window_seconds": None,
                "window_documents": 120,
                "average_documents_per_second": 120 / 86400,
                "average_documents_per_minute": None,
                "average_documents_per_hour": None,
                "average_documents_per_day": None,
                "index_stats": {},
                "buckets": [{"key_as_string": "2026-11-04T00:00:00Z", "documents": 5}],
            },
            {
                "index": "logs-*",
                "timestamp_field": "@timestamp",
                "lookback": "24h",
                "interval": None,
                "window_seconds": None,
                "window_documents": 120,
                "average_documents_per_second": 120 / 86400,
                "average_documents_per_minute": None,
                "average_documents_per_hour": None,
                "average_documents_per_day": None,
                "index_stats": {},
                "buckets": [{"key_as_string": "2026-11-04T00:00:00Z", "documents": 5}],
            },
        ),
    ],
)
def test_field_and_metric_parsers_keep_workflow_relevant_data(
    tmp_path: Path,
    command: str,
    data: dict[str, object],
    expected_context: dict[str, object],
) -> None:
    raw_path = (
        tmp_path
        / "outputs"
        / "raw"
        / "elastic_cluster-1"
        / "2026-11-04"
        / f"{command}.json"
    )
    raw_path.parent.mkdir(parents=True)
    raw_path.write_text(
        json.dumps(
            {
                "command": command,
                "collected_at": "2026-11-04T12:00:00+05:30",
                "cluster": {"name": "elastic", "uuid": "cluster-1"},
                "arguments": {},
                "data": data,
            }
        ),
        encoding="utf-8",
    )

    parsed = parse_raw_snapshot(raw_path)

    assert parsed["security_context"] == expected_context


@pytest.mark.parametrize(
    ("value", "expected"),
    [("30s", 30), ("5m", 300), ("2h", 7200), ("1d", 86400)],
)
def test_duration_seconds(value: str, expected: int) -> None:
    assert _duration_seconds(value, "lookback") == expected


@pytest.mark.parametrize("value", ["0h", "-1h", "3w", "1.5h", "h"])
def test_duration_rejects_invalid_values(value: str) -> None:
    with pytest.raises(ValueError):
        _duration_seconds(value, "lookback")


def test_blank_optional_kibana_url_is_unset() -> None:
    settings = Settings(kibana_url="")

    assert settings.kibana_url is None


def test_insecure_request_warning_suppression_is_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    suppressed: list[type[Warning]] = []
    warning_filters: list[tuple[str, type[Warning]]] = []
    monkeypatch.setattr(urllib3, "disable_warnings", suppressed.append)
    monkeypatch.setattr(
        warnings,
        "filterwarnings",
        lambda action, category: warning_filters.append((action, category)),
    )

    Settings(suppress_insecure_request_warnings=False).configure_tls_warnings()
    assert suppressed == []
    assert warning_filters == []

    Settings(suppress_insecure_request_warnings=True).configure_tls_warnings()
    assert suppressed == [InsecureRequestWarning]
    assert warning_filters == [("ignore", SecurityWarning)]


def test_elasticsearch_security_warning_is_suppressed_when_enabled() -> None:
    settings = Settings(suppress_insecure_request_warnings=True)

    with warnings.catch_warnings(record=True) as caught:
        settings.configure_tls_warnings()
        warnings.warn("TLS verification is disabled", SecurityWarning)

    assert caught == []


def test_mapping_flattener_includes_nested_and_multifields() -> None:
    fields = flatten_mapping(
        {
            "host": {"properties": {"name": {"type": "keyword"}}},
            "message": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
        }
    )

    assert [field["name"] for field in fields] == [
        "host",
        "host.name",
        "message",
        "message.keyword",
    ]


def test_runtime_fields_are_marked_as_runtime() -> None:
    fields = flatten_runtime_fields({"risk_score": {"type": "long"}})

    assert fields == [{"name": "risk_score", "type": "long", "origin": "runtime"}]


def test_event_bus_publishes_to_subscribers() -> None:
    received: list[WorkflowEvent] = []
    bus = EventBus()
    bus.subscribe("command.completed", received.append)
    event = WorkflowEvent("command.completed", {"command": "cluster"})

    bus.publish(event)

    assert received == [event]
