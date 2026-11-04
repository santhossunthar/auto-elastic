import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


_UNSAFE_PATH_CHARACTERS = re.compile(r"[^A-Za-z0-9._-]+")


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _safe_component(value: str, fallback: str) -> str:
    component = _UNSAFE_PATH_CHARACTERS.sub("_", value).strip("._-")
    return component[:80] or fallback


def _argument_slug(arguments: dict[str, Any]) -> str:
    parts: list[str] = []
    for key, value in sorted(arguments.items()):
        if key in {"command", "output_file", "handler"} or value is None or value is False:
            continue
        option = _safe_component(key.replace("_", "-"), "option").lower()
        if value is True:
            parts.append(option)
            continue
        rendered_value = str(value).lower().replace("*", "all").replace("?", "any")
        rendered_value = _safe_component(rendered_value, "value").lower()
        rendered_value = _limit_filename_stem(rendered_value, max_length=32)
        parts.append(f"{option}-{rendered_value}")
    return "__".join(parts)


def _limit_filename_stem(value: str, max_length: int = 100) -> str:
    if len(value) <= max_length:
        return value
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]
    return f"{value[:max_length - len(digest) - 2]}__{digest}"


def _cluster_directory(cluster_info: dict[str, Any]) -> str:
    name = _safe_component(str(cluster_info.get("cluster_name") or ""), "unknown-cluster")
    cluster_uuid = cluster_info.get("cluster_uuid")
    if cluster_uuid and cluster_uuid != "_na_":
        return f"{name}_{_safe_component(str(cluster_uuid), 'unknown-id')}"
    return name


def _endpoint_identity(endpoint: str) -> dict[str, Any]:
    parsed = urlsplit(endpoint)
    return {
        "scheme": parsed.scheme,
        "host": parsed.hostname,
        "port": parsed.port,
    }


def _cluster_version(cluster_info: dict[str, Any]) -> Any:
    version = cluster_info.get("version")
    return version.get("number") if isinstance(version, dict) else None


def write_snapshot(
    *,
    command: str,
    arguments: dict[str, Any],
    cluster_info: dict[str, Any],
    endpoint: str,
    data: dict[str, Any],
    output_root: Path | None = None,
    collected_at: datetime | None = None,
) -> Path:
    timestamp = collected_at or datetime.now().astimezone()
    if timestamp.tzinfo is None:
        raise ValueError("collected_at must be timezone-aware")

    snapshot = {
        "schema_version": "1.0",
        "collected_at": timestamp.isoformat(timespec="microseconds"),
        "cluster": {
            "name": cluster_info.get("cluster_name"),
            "uuid": cluster_info.get("cluster_uuid"),
            "version": _cluster_version(cluster_info),
            "endpoint": _endpoint_identity(endpoint),
        },
        "command": command,
        "arguments": arguments,
        "data": data,
    }

    root = output_root or project_root()
    date_directory = timestamp.strftime("%Y-%m-%d")
    output_directory = (
        root / "outputs" / "raw" / _cluster_directory(cluster_info) / date_directory
    )
    output_directory.mkdir(parents=True, exist_ok=True)

    base_name = _safe_component(command, "command")
    argument_slug = _argument_slug(arguments)
    if argument_slug:
        base_name = f"{base_name}__{argument_slug}"
    base_name = _limit_filename_stem(base_name)
    filename_timestamp = timestamp.astimezone(timezone.utc).strftime(
        "%Y%m%dT%H%M%S.%fZ"
    )
    max_stem_length = min(
        100,
        230
        - len(str(output_directory))
        - 1
        - len(filename_timestamp)
        - 2
        - len(".json")
        - 4,
    )
    if max_stem_length < 24:
        raise ValueError(
            "snapshot output path is too long for a portable filename; "
            "use a shorter project path"
        )
    base_name = _limit_filename_stem(base_name, max_length=max_stem_length)
    base_name = f"{filename_timestamp}__{base_name}"
    revision = 1
    while True:
        suffix = "" if revision == 1 else f"_{revision:02d}"
        output_path = output_directory / f"{base_name}{suffix}.json"
        try:
            with output_path.open("x", encoding="utf-8", newline="\n") as output_file:
                json.dump(snapshot, output_file, indent=2, ensure_ascii=False, allow_nan=False)
                output_file.write("\n")
            return output_path
        except FileExistsError:
            revision += 1


def write_parsed_snapshot(
    *,
    raw_path: Path,
    parsed_snapshot: dict[str, Any],
    output_root: Path | None = None,
) -> Path:
    root = output_root or project_root()
    raw_directory = (root / "outputs" / "raw").resolve()
    try:
        raw_relative_path = raw_path.resolve().relative_to(raw_directory)
    except ValueError as error:
        raise ValueError("raw snapshot must be located under outputs/raw") from error

    parsed_path = root / "outputs" / "parsed" / raw_relative_path
    parsed_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with parsed_path.open("x", encoding="utf-8", newline="\n") as output_file:
            json.dump(
                parsed_snapshot,
                output_file,
                indent=2,
                ensure_ascii=False,
                allow_nan=False,
            )
            output_file.write("\n")
    except FileExistsError as error:
        raise FileExistsError(f"parsed snapshot already exists: {parsed_path}") from error
    return parsed_path


def write_latest_summary(
    *,
    command: str,
    cluster_info: dict[str, Any],
    parsed_snapshot: dict[str, Any],
    simple: bool = False,
    output_root: Path | None = None,
) -> Path:
    root = output_root or project_root()
    cluster_directory = _cluster_directory(cluster_info)
    summary_directory = root / "outputs" / "summary" / cluster_directory
    summary_directory.mkdir(parents=True, exist_ok=True)
    filename = _safe_component(command, "command")
    if simple:
        filename = f"{filename}-simple"
    summary_path = summary_directory / f"{filename}.json"

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=summary_directory,
            prefix=f".{summary_path.stem}.",
            suffix=".tmp",
            delete=False,
        ) as output_file:
            temporary_path = Path(output_file.name)
            json.dump(
                parsed_snapshot,
                output_file,
                indent=2,
                ensure_ascii=False,
                allow_nan=False,
            )
            output_file.write("\n")
            output_file.flush()
            os.fsync(output_file.fileno())
        os.replace(temporary_path, summary_path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()
    return summary_path


def write_latest_markdown_summary(
    *,
    command: str,
    cluster_info: dict[str, Any],
    content: str,
    simple: bool = False,
    output_root: Path | None = None,
) -> Path:
    root = output_root or project_root()
    summary_directory = (
        root / "outputs" / "summary" / _cluster_directory(cluster_info)
    )
    summary_directory.mkdir(parents=True, exist_ok=True)
    filename = _safe_component(command, "command")
    if simple:
        filename = f"{filename}-simple"
    summary_path = summary_directory / f"{filename}.md"

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=summary_directory,
            prefix=f".{summary_path.stem}.",
            suffix=".tmp",
            delete=False,
        ) as output_file:
            temporary_path = Path(output_file.name)
            output_file.write(content)
            if not content.endswith("\n"):
                output_file.write("\n")
            output_file.flush()
            os.fsync(output_file.fileno())
        os.replace(temporary_path, summary_path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()
    return summary_path
