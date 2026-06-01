from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from .extract import iter_extraction_jobs, run_extraction
from .normalize import normalize_directory
from .targets import TARGET_BRANCHES


def read_host_name(input_root: Path) -> str | None:
    manifest = input_root / "manifest.json"
    if not manifest.is_file():
        return None

    try:
        with manifest.open("r", encoding="utf-8-sig") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None

    host_name = data.get("host_name")
    return str(host_name) if host_name else None


def command_extract(args: argparse.Namespace) -> int:
    count = run_extraction(args.input, args.output, args.recmd)
    print(f"Created extraction jobs: {count}")
    return 0


def command_normalize(args: argparse.Namespace) -> int:
    host_name = args.host or read_host_name(args.source_root or args.input)
    count = normalize_directory(args.input, args.output, host_name=host_name)
    print(f"Wrote normalized registry records: {count}")
    return 0


def command_process(args: argparse.Namespace) -> int:
    output = args.output or (args.input / "processed" / "Registry.json")
    extracted_dir = args.extracted_dir or (output.parent / "extracted")
    host_name = args.host or read_host_name(args.input)

    count_jobs = run_extraction(args.input, extracted_dir, args.recmd)
    count_records = normalize_directory(extracted_dir, output, host_name=host_name)

    if not args.keep_extracted and extracted_dir.exists():
        shutil.rmtree(extracted_dir)

    print(f"Created extraction jobs: {count_jobs}")
    print(f"Wrote normalized registry records: {count_records}")
    print(f"Output: {output}")
    return 0


def command_print_targets(_: argparse.Namespace) -> int:
    for hive_kind, branches in TARGET_BRANCHES.items():
        print(f"[{hive_kind}]")
        for branch in branches:
            print(branch)
        print()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="persist-detector",
        description="Process Windows persistence registry artifacts for Wazuh.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    extract = subparsers.add_parser("extract", help="Run RECmd targeted extraction against uploaded hives.")
    extract.add_argument("--input", type=Path, required=True, help="Uploaded host directory.")
    extract.add_argument("--output", type=Path, required=True, help="Directory for RECmd JSON output.")
    extract.add_argument("--recmd", type=Path, required=True, help="Path to RECmd.exe or RECmd wrapper.")
    extract.set_defaults(func=command_extract)

    normalize = subparsers.add_parser("normalize", help="Normalize RECmd JSON into Registry.json NDJSON.")
    normalize.add_argument("--input", type=Path, required=True, help="Directory containing RECmd JSON files.")
    normalize.add_argument("--output", type=Path, required=True, help="Output NDJSON file.")
    normalize.add_argument("--source-root", type=Path, help="Uploaded host directory containing manifest.json.")
    normalize.add_argument("--host", help="Host name to add to normalized records.")
    normalize.set_defaults(func=command_normalize)

    process = subparsers.add_parser("process", help="Run extraction and normalization.")
    process.add_argument("--input", type=Path, required=True, help="Uploaded host directory.")
    process.add_argument("--output", type=Path, help="Output NDJSON file. Defaults to <input>/processed/Registry.json.")
    process.add_argument("--recmd", type=Path, required=True, help="Path to RECmd.exe or RECmd wrapper.")
    process.add_argument("--extracted-dir", type=Path, help="Directory for intermediate RECmd JSON.")
    process.add_argument("--host", help="Host name to add to normalized records.")
    process.add_argument("--keep-extracted", action="store_true", help="Keep intermediate RECmd JSON files.")
    process.set_defaults(func=command_process)

    print_targets = subparsers.add_parser("print-targets", help="Print configured registry extraction branches.")
    print_targets.set_defaults(func=command_print_targets)

    jobs = subparsers.add_parser("list-jobs", help="List RECmd extraction jobs for an uploaded host directory.")
    jobs.add_argument("--input", type=Path, required=True, help="Uploaded host directory.")
    jobs.set_defaults(func=command_list_jobs)

    return parser


def command_list_jobs(args: argparse.Namespace) -> int:
    for job in iter_extraction_jobs(args.input):
        print(f"{job.hive_kind}\t{job.hive_path}\t{job.branch}\t{job.output_name}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
