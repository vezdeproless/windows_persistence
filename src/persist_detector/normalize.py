from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Iterable

from .targets import match_detection_rules, techniques_for_key_path


UTC_MINUS_3 = timezone(timedelta(hours=-3))

VALUE_TYPE_KEYS = ("ValueType", "ValueTypeName", "Type", "DataType")
VALUE_NAME_KEYS = ("ValueName", "Name")
VALUE_DATA_KEYS = ("ValueData", "Data", "Value", "ValueDataRaw", "DataRaw")
TIMESTAMP_KEYS = ("LastWriteTime", "LastWriteTimestamp", "LastWriteTimeUtc", "Timestamp")


@dataclass(frozen=True)
class SourceContext:
    hive_kind: str
    root_label: str
    username: str | None = None


def infer_source_context(path: Path) -> SourceContext:
    stem = path.stem
    lowered = stem.lower()

    if lowered.startswith("ntuser-"):
        remainder = stem[len("NTUSER-") :]
        username = remainder.rsplit("-", 1)[0] if "-" in remainder else remainder
        return SourceContext("NTUSER", f"NTUSER.DAT-{username}", username)

    if lowered.startswith("usrclass-"):
        remainder = stem[len("UsrClass-") :]
        username = remainder.rsplit("-", 1)[0] if "-" in remainder else remainder
        return SourceContext("USRCLASS", f"UsrClass-{username}", username)

    if lowered.startswith("system"):
        return SourceContext("SYSTEM", "System")

    return SourceContext("SOFTWARE", "Software")


def first_present(mapping: dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def iter_key_nodes(node: Any) -> Iterable[dict[str, Any]]:
    if isinstance(node, list):
        for item in node:
            yield from iter_key_nodes(item)
        return

    if not isinstance(node, dict):
        return

    has_key_shape = any(key in node for key in ("KeyPath", "KeyName", "Values", "SubKeys"))
    if has_key_shape:
        yield node

    subkeys = node.get("SubKeys")
    if isinstance(subkeys, list):
        for child in subkeys:
            yield from iter_key_nodes(child)

    if not has_key_shape:
        for value in node.values():
            if isinstance(value, (dict, list)):
                yield from iter_key_nodes(value)


def normalize_key_path(key_path: str, context: SourceContext) -> str:
    path = key_path.replace("/", "\\").strip("\\")
    upper = path.upper()

    if upper == "ROOT":
        return context.root_label

    if upper.startswith("ROOT\\"):
        suffix = path[5:]
        return f"{context.root_label}\\{suffix}" if suffix else context.root_label

    if upper.startswith("HKEY_LOCAL_MACHINE\\SOFTWARE\\"):
        return "Software\\" + path.split("\\", 2)[2]

    if upper == "HKEY_LOCAL_MACHINE\\SOFTWARE":
        return "Software"

    if upper.startswith("HKEY_LOCAL_MACHINE\\SYSTEM\\"):
        return "System\\" + path.split("\\", 2)[2]

    if upper == "HKEY_LOCAL_MACHINE\\SYSTEM":
        return "System"

    if upper.startswith("HKEY_CURRENT_USER\\"):
        return f"{context.root_label}\\" + path.split("\\", 1)[1]

    if upper == "HKEY_CURRENT_USER":
        return context.root_label

    if context.hive_kind == "SOFTWARE" and not upper.startswith("SOFTWARE"):
        return f"Software\\{path}"

    if context.hive_kind == "SYSTEM" and not upper.startswith("SYSTEM"):
        return f"System\\{path}"

    if context.hive_kind in {"NTUSER", "USRCLASS"} and not upper.startswith(context.root_label.upper()):
        return f"{context.root_label}\\{path}"

    return path


def is_empty_value(value: Any) -> bool:
    if value is None:
        return True

    if isinstance(value, str):
        return value.strip() == ""

    if isinstance(value, (list, tuple, dict)):
        return len(value) == 0

    return False


def is_numeric_only(value: Any) -> bool:
    if isinstance(value, bool):
        return False

    if isinstance(value, (int, float)):
        return True

    if isinstance(value, str):
        return re.fullmatch(r"[+-]?\d+(?:\.\d+)?", value.strip()) is not None

    if isinstance(value, (list, tuple)):
        return bool(value) and all(is_numeric_only(item) for item in value)

    return False


def parse_timestamp(value: Any) -> str | None:
    if value in (None, ""):
        return None

    text = str(value).strip().replace("Z", "+00:00")
    if " " in text and "T" not in text:
        text = text.replace(" ", "T", 1)

    text = re.sub(r"(\.\d{6})\d+", r"\1", text)

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(UTC_MINUS_3).strftime("%Y-%m-%dT%H:%M:%S")


def normalize_value_data(value: Any) -> Any:
    if isinstance(value, str):
        return value.strip()

    if isinstance(value, list):
        return [normalize_value_data(item) for item in value]

    return value


def build_record(
    *,
    node: dict[str, Any],
    value: dict[str, Any],
    context: SourceContext,
    source_file: Path,
    host_name: str | None,
) -> dict[str, Any] | None:
    value_type = first_present(value, VALUE_TYPE_KEYS)
    value_data = normalize_value_data(first_present(value, VALUE_DATA_KEYS))

    if is_empty_value(value_type) or is_empty_value(value_data) or is_numeric_only(value_data):
        return None

    raw_key_path = str(node.get("KeyPath") or node.get("Path") or node.get("KeyName") or "ROOT")
    key_path = normalize_key_path(raw_key_path, context)
    key_name = str(node.get("KeyName") or key_path.rsplit("\\", 1)[-1])
    value_name = first_present(value, VALUE_NAME_KEYS)
    timestamp = parse_timestamp(first_present(node, TIMESTAMP_KEYS))

    record: dict[str, Any] = {
        "event.module": "windows-persistence-detection",
        "event.dataset": "windows.registry.persistence",
        "event.category": "registry",
        "event.type": "info",
        "registry.hive": context.hive_kind,
        "registry.source.file": source_file.name,
        "registry.value.type": str(value_type),
        "reg.key.path": key_path,
        "reg.key.name": key_name,
        "file.name": "" if value_name is None else str(value_name),
        "file.path": value_data,
    }

    if timestamp:
        record["@timestamp"] = timestamp

    if host_name:
        record["host.name"] = host_name

    techniques = techniques_for_key_path(key_path)
    if techniques:
        record["threat.technique.id"] = ",".join(techniques)
        record["rule.description"] = "; ".join(
            sorted({rule.description for rule in match_detection_rules(key_path)})
        )

    if context.username:
        record["user.name"] = context.username

    return record


def normalize_recmd_json(path: Path, host_name: str | None = None) -> list[dict[str, Any]]:
    context = infer_source_context(path)

    with path.open("r", encoding="utf-8-sig") as handle:
        data = json.load(handle)

    records: list[dict[str, Any]] = []

    for node in iter_key_nodes(data):
        values = node.get("Values")
        if not isinstance(values, list):
            continue

        for value in values:
            if not isinstance(value, dict):
                continue

            record = build_record(
                node=node,
                value=value,
                context=context,
                source_file=path,
                host_name=host_name,
            )
            if record is not None:
                records.append(record)

    return records


def normalize_directory(input_dir: Path, output_file: Path, host_name: str | None = None) -> int:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_resolved = output_file.resolve() if output_file.exists() else output_file.absolute()
    count = 0

    with output_file.open("w", encoding="utf-8") as handle:
        for json_path in sorted(input_dir.rglob("*.json")):
            if json_path.resolve() == output_resolved:
                continue

            for record in normalize_recmd_json(json_path, host_name=host_name):
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
                handle.write("\n")
                count += 1

    return count
