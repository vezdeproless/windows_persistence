from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from .extract import iter_extraction_jobs, run_extraction
from .hunt import DEFAULT_RARE_THRESHOLD, write_hunt_report
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


def default_hunt_output(input_files: list[Path]) -> Path:
    if len(input_files) != 1:
        raise SystemExit("--output is required when more than one --input file is provided")

    return input_files[0].parent / "PersistenceHunt.json"


def command_hunt(args: argparse.Namespace) -> int:
    if args.rare_threshold < 1:
        raise SystemExit("--rare-threshold must be greater than zero")

    output = args.output or default_hunt_output(args.input)
    count = write_hunt_report(args.input, output, rare_threshold=args.rare_threshold)
    print(f"Wrote persistence hunt records: {count}")
    print(f"Output: {output}")
    return 0


def command_process(args: argparse.Namespace) -> int:
    if args.rare_threshold < 1:
        raise SystemExit("--rare-threshold must be greater than zero")

    output = args.output or (args.input / "processed" / "Registry.json")
    extracted_dir = args.extracted_dir or (output.parent / "extracted")
    hunt_output = args.hunt_output or (output.parent / "PersistenceHunt.json")
    host_name = args.host or read_host_name(args.input)

    count_jobs = run_extraction(args.input, extracted_dir, args.recmd)
    count_records = normalize_directory(extracted_dir, output, host_name=host_name)
    count_hunt_records = 0

    if not args.skip_hunt:
        count_hunt_records = write_hunt_report([output], hunt_output, rare_threshold=args.rare_threshold)

    if count_records == 0:
        print(f"Warning: no normalized records were written. Kept extracted JSON for inspection: {extracted_dir}")
    elif not args.keep_extracted and extracted_dir.exists():
        shutil.rmtree(extracted_dir)

    print(f"Created extraction jobs: {count_jobs}")
    print(f"Wrote normalized registry records: {count_records}")
    print(f"Output: {output}")
    if not args.skip_hunt:
        print(f"Wrote persistence hunt records: {count_hunt_records}")
        print(f"Hunt output: {hunt_output}")
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

    hunt = subparsers.add_parser("hunt", help="Build frequency-analysis NDJSON from Registry.json.")
    hunt.add_argument("--input", type=Path, required=True, nargs="+", help="One or more Registry.json files.")
    hunt.add_argument("--output", type=Path, help="Output NDJSON file. Defaults to PersistenceHunt.json next to one input.")
    hunt.add_argument(
        "--rare-threshold",
        type=int,
        default=DEFAULT_RARE_THRESHOLD,
        help=f"Maximum occurrence count treated as rare. Default: {DEFAULT_RARE_THRESHOLD}.",
    )
    hunt.set_defaults(func=command_hunt)

    process = subparsers.add_parser("process", help="Run extraction and normalization.")
    process.add_argument("--input", type=Path, required=True, help="Uploaded host directory.")
    process.add_argument("--output", type=Path, help="Output NDJSON file. Defaults to <input>/processed/Registry.json.")
    process.add_argument("--recmd", type=Path, required=True, help="Path to RECmd.exe or RECmd wrapper.")
    process.add_argument("--extracted-dir", type=Path, help="Directory for intermediate RECmd JSON.")
    process.add_argument("--host", help="Host name to add to normalized records.")
    process.add_argument("--keep-extracted", action="store_true", help="Keep intermediate RECmd JSON files.")
    process.add_argument("--hunt-output", type=Path, help="Output NDJSON file for frequency-analysis records.")
    process.add_argument("--skip-hunt", action="store_true", help="Do not build PersistenceHunt.json.")
    process.add_argument(
        "--rare-threshold",
        type=int,
        default=DEFAULT_RARE_THRESHOLD,
        help=f"Maximum occurrence count treated as rare. Default: {DEFAULT_RARE_THRESHOLD}.",
    )
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
