from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable


UTC_MINUS_3 = timezone(timedelta(hours=-3))
DEFAULT_RARE_THRESHOLD = 2

HIGH_RISK_TECHNIQUES = {
    "T1505/005",
    "T1546/008",
    "T1546/011",
    "T1546/012",
    "T1556/002",
    "T1556/008",
    "T1574/011",
    "T1574/012",
}

LOLBIN_PATTERN = re.compile(
    r"\b(?:powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)"
    r"(?:\.exe)?\b",
    re.IGNORECASE,
)


@dataclass
class GroupAccumulator:
    count: int = 0
    hosts: set[str] = field(default_factory=set)
    registry_locations: set[str] = field(default_factory=set)
    registry_value_names: set[str] = field(default_factory=set)
    executable_paths: set[str] = field(default_factory=set)
    techniques: set[str] = field(default_factory=set)
    timestamps: list[str] = field(default_factory=list)
    anomaly_reasons: set[str] = field(default_factory=set)

    def add(self, record: dict[str, Any]) -> None:
        self.count += 1
        _add_string(self.hosts, record.get("host.name"))
        _add_string(self.registry_locations, record.get("reg.key.path"))
        _add_string(self.registry_value_names, record.get("file.name"))
        _add_string(self.executable_paths, record.get("file.path"))

        timestamp = stringify_value(record.get("@timestamp"))
        if timestamp:
            self.timestamps.append(timestamp)

        self.techniques.update(split_techniques(record.get("threat.technique.id")))
        self.anomaly_reasons.update(detect_executable_anomalies(record.get("file.path")))


def _add_string(values: set[str], value: Any) -> None:
    text = stringify_value(value)
    if text:
        values.add(text)


def stringify_value(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, str):
        return value.strip()

    if isinstance(value, (list, tuple)):
        parts = [stringify_value(item) for item in value]
        return " | ".join(part for part in parts if part)

    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)

    return str(value).strip()


def split_techniques(value: Any) -> set[str]:
    text = stringify_value(value)
    if not text:
        return set()

    return {part.strip() for part in re.split(r"[,;]", text) if part.strip()}


def read_registry_records(input_files: Iterable[Path]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    for input_file in input_files:
        with input_file.open("r", encoding="utf-8-sig") as handle:
            for line_number, line in enumerate(handle, start=1):
                stripped = line.strip()
                if not stripped:
                    continue

                try:
                    record = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid JSON in {input_file}:{line_number}: {exc}") from exc

                if isinstance(record, dict):
                    records.append(record)

    return records


def detect_executable_anomalies(value: Any) -> set[str]:
    text = stringify_value(value)
    if not text:
        return set()

    lowered = text.replace("/", "\\").lower()
    reasons: set[str] = set()

    suspicious_markers = (
        ("user_public_path", "\\users\\public\\"),
        ("temp_path", "\\temp\\"),
        ("downloads_path", "\\downloads\\"),
        ("appdata_path", "\\appdata\\"),
        ("programdata_path", "\\programdata\\"),
        ("recycle_bin_path", "\\$recycle.bin\\"),
    )

    for reason, marker in suspicious_markers:
        if marker in lowered:
            reasons.add(reason)

    if lowered.startswith("\\\\"):
        reasons.add("unc_path")

    if "http://" in lowered or "https://" in lowered:
        reasons.add("url_in_command")

    if LOLBIN_PATTERN.search(lowered):
        reasons.add("living_off_the_land_binary")

    if re.search(r"(^|[\s\"'])[a-z]:\\[^\\\s]+(?:\.exe|\.dll|\.scr|\.bat|\.cmd|\.ps1|\.vbs|\.js)\b", lowered):
        reasons.add("drive_root_path")

    if re.search(r"\.scr(?:\s|$|\"|')", lowered):
        reasons.add("screensaver_binary")

    return reasons


def classify_rarity(count: int, rare_threshold: int) -> str:
    if count <= 1:
        return "unique"

    if count <= rare_threshold:
        return "rare"

    return "common"


def calculate_score(accumulator: GroupAccumulator, rarity: str) -> int:
    score = 0

    if rarity == "unique":
        score += 30
    elif rarity == "rare":
        score += 15

    if accumulator.anomaly_reasons:
        score += 40

    if accumulator.techniques & HIGH_RISK_TECHNIQUES:
        score += 25

    return min(score, 100)


def _join_sample(values: Iterable[str], limit: int = 10) -> str:
    return " || ".join(sorted(values)[:limit])


def _timestamp_bounds(timestamps: list[str]) -> tuple[str, str]:
    if not timestamps:
        return "", ""

    sorted_timestamps = sorted(timestamps)
    return sorted_timestamps[0], sorted_timestamps[-1]


def _base_hunt_record(
    *,
    kind: str,
    group_field: str,
    group_value: str,
    accumulator: GroupAccumulator,
    rank: int,
    total_groups: int,
    total_records: int,
    rare_threshold: int,
    generated_at: str,
) -> dict[str, Any]:
    rarity = classify_rarity(accumulator.count, rare_threshold)
    score = calculate_score(accumulator, rarity)
    first_seen, last_seen = _timestamp_bounds(accumulator.timestamps)
    host_names = sorted(accumulator.hosts)

    record: dict[str, Any] = {
        "@timestamp": generated_at,
        "event.module": "windows-persistence-detection",
        "event.dataset": "windows.registry.persistence.hunt",
        "event.category": "registry",
        "event.type": "info",
        "event.action": "frequency-analysis",
        "hunt.kind": kind,
        "hunt.group.field": group_field,
        "hunt.group.value": group_value,
        "hunt.suspicious": "true" if score >= 40 else "false",
        "hunt.score": score,
        "frequency.count": accumulator.count,
        "frequency.rank": rank,
        "frequency.rarity": rarity,
        "frequency.rare.threshold": rare_threshold,
        "frequency.total.groups": total_groups,
        "frequency.total.records": total_records,
        "host.count": len(host_names),
        "host.name": host_names[0] if len(host_names) == 1 else "multiple",
        "host.names": _join_sample(host_names),
        "registry.location.count": len(accumulator.registry_locations),
        "registry.value.name.count": len(accumulator.registry_value_names),
        "executable.path.count": len(accumulator.executable_paths),
        "analysis.generated_at": generated_at,
        "anomaly.executable.path": "true" if accumulator.anomaly_reasons else "false",
        "anomaly.executable.reason": _join_sample(accumulator.anomaly_reasons),
    }

    techniques = sorted(accumulator.techniques)
    if techniques:
        record["threat.technique.id"] = ",".join(techniques)

    if first_seen:
        record["registry.last_write.first"] = first_seen
        record["registry.last_write.last"] = last_seen

    return record


def _sorted_groups(groups: dict[Any, GroupAccumulator]) -> list[tuple[Any, GroupAccumulator]]:
    return sorted(groups.items(), key=lambda item: (item[1].count, stringify_value(item[0])))


def build_hunt_records(
    registry_records: Iterable[dict[str, Any]],
    *,
    rare_threshold: int = DEFAULT_RARE_THRESHOLD,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    if rare_threshold < 1:
        raise ValueError("rare_threshold must be greater than zero")

    records = list(registry_records)
    generated = generated_at or datetime.now(UTC_MINUS_3).strftime("%Y-%m-%dT%H:%M:%S")
    total_records = len(records)

    path_groups: dict[str, GroupAccumulator] = defaultdict(GroupAccumulator)
    key_groups: dict[str, GroupAccumulator] = defaultdict(GroupAccumulator)
    entry_groups: dict[tuple[str, str, str], GroupAccumulator] = defaultdict(GroupAccumulator)

    for record in records:
        executable_path = stringify_value(record.get("file.path"))
        key_path = stringify_value(record.get("reg.key.path"))
        value_name = stringify_value(record.get("file.name"))

        if executable_path:
            path_groups[executable_path].add(record)

        if key_path:
            key_groups[key_path].add(record)

        if key_path or executable_path:
            entry_groups[(key_path, value_name, executable_path)].add(record)

    hunt_records: list[dict[str, Any]] = []
    hunt_records.extend(
        _build_group_records(
            kind="executable_path",
            group_field="file.path",
            groups=path_groups,
            total_records=total_records,
            rare_threshold=rare_threshold,
            generated_at=generated,
        )
    )
    hunt_records.extend(
        _build_group_records(
            kind="registry_location",
            group_field="reg.key.path",
            groups=key_groups,
            total_records=total_records,
            rare_threshold=rare_threshold,
            generated_at=generated,
        )
    )
    hunt_records.extend(
        _build_entry_records(
            groups=entry_groups,
            total_records=total_records,
            rare_threshold=rare_threshold,
            generated_at=generated,
        )
    )

    return hunt_records


def _build_group_records(
    *,
    kind: str,
    group_field: str,
    groups: dict[str, GroupAccumulator],
    total_records: int,
    rare_threshold: int,
    generated_at: str,
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    sorted_groups = _sorted_groups(groups)
    total_groups = len(sorted_groups)

    for rank, (group_value, accumulator) in enumerate(sorted_groups, start=1):
        record = _base_hunt_record(
            kind=kind,
            group_field=group_field,
            group_value=group_value,
            accumulator=accumulator,
            rank=rank,
            total_groups=total_groups,
            total_records=total_records,
            rare_threshold=rare_threshold,
            generated_at=generated_at,
        )

        if kind == "executable_path":
            record["file.path"] = group_value
            record["reg.key.path"] = _join_sample(accumulator.registry_locations)
            record["file.name"] = _join_sample(accumulator.registry_value_names)
        else:
            record["reg.key.path"] = group_value
            record["file.path"] = _join_sample(accumulator.executable_paths)
            record["file.name"] = _join_sample(accumulator.registry_value_names)

        output.append(record)

    return output


def _build_entry_records(
    *,
    groups: dict[tuple[str, str, str], GroupAccumulator],
    total_records: int,
    rare_threshold: int,
    generated_at: str,
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    sorted_groups = _sorted_groups(groups)
    total_groups = len(sorted_groups)

    for rank, ((key_path, value_name, executable_path), accumulator) in enumerate(sorted_groups, start=1):
        group_value = f"{key_path} | {value_name} | {executable_path}"
        record = _base_hunt_record(
            kind="persistence_entry",
            group_field="reg.key.path,file.name,file.path",
            group_value=group_value,
            accumulator=accumulator,
            rank=rank,
            total_groups=total_groups,
            total_records=total_records,
            rare_threshold=rare_threshold,
            generated_at=generated_at,
        )
        record["reg.key.path"] = key_path
        record["file.name"] = value_name
        record["file.path"] = executable_path
        output.append(record)

    return output


def write_hunt_report(
    input_files: Iterable[Path],
    output_file: Path,
    *,
    rare_threshold: int = DEFAULT_RARE_THRESHOLD,
) -> int:
    records = read_registry_records(input_files)
    hunt_records = build_hunt_records(records, rare_threshold=rare_threshold)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8") as handle:
        for record in hunt_records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
            handle.write("\n")

    return len(hunt_records)
