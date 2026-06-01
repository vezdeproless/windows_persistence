from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from .targets import TARGET_BRANCHES


@dataclass(frozen=True)
class ExtractionJob:
    hive_kind: str
    hive_path: Path
    branch: str
    output_name: str
    username: str | None = None


def safe_filename_part(value: str) -> str:
    return value.replace("\\", "%5C").replace(" ", "")


def _iter_dat_files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []

    return sorted(path for path in directory.iterdir() if path.is_file() and path.suffix.lower() == ".dat")


def discover_hives(input_root: Path) -> dict[str, list[tuple[Path, str | None]]]:
    reg_dir = input_root / "Reg"
    ntuser_dir = input_root / "NTUSER"
    usrclass_dir = input_root / "UsrClass"

    hives: dict[str, list[tuple[Path, str | None]]] = {
        "SOFTWARE": [],
        "SYSTEM": [],
        "NTUSER": [],
        "USRCLASS": [],
    }

    software = reg_dir / "SOFTWARE"
    if software.is_file():
        hives["SOFTWARE"].append((software, None))

    system = reg_dir / "SYSTEM"
    if system.is_file():
        hives["SYSTEM"].append((system, None))

    for hive_path in _iter_dat_files(ntuser_dir):
        hives["NTUSER"].append((hive_path, hive_path.stem))

    for hive_path in _iter_dat_files(usrclass_dir):
        hives["USRCLASS"].append((hive_path, hive_path.stem))

    return hives


def iter_extraction_jobs(input_root: Path) -> list[ExtractionJob]:
    jobs: list[ExtractionJob] = []

    for hive_kind, hive_files in discover_hives(input_root).items():
        branches = TARGET_BRANCHES[hive_kind]

        for hive_path, username in hive_files:
            if hive_kind == "NTUSER":
                hive_label = f"NTUSER-{safe_filename_part(username or 'unknown')}"
            elif hive_kind == "USRCLASS":
                hive_label = f"UsrClass-{safe_filename_part(username or 'unknown')}"
            else:
                hive_label = hive_kind

            for branch in branches:
                output_name = f"{hive_label}-{safe_filename_part(branch)}.json"
                jobs.append(
                    ExtractionJob(
                        hive_kind=hive_kind,
                        hive_path=hive_path,
                        branch=branch,
                        output_name=output_name,
                        username=username,
                    )
                )

    return jobs


def run_extraction(input_root: Path, output_dir: Path, recmd: Path) -> int:
    jobs = iter_extraction_jobs(input_root)
    if not jobs:
        raise FileNotFoundError(f"No supported registry hives found below {input_root}")

    output_dir.mkdir(parents=True, exist_ok=True)

    for job in jobs:
        command = [
            str(recmd),
            "--f",
            str(job.hive_path),
            "--kn",
            job.branch,
            "--json",
            str(output_dir),
            "--jsonf",
            job.output_name,
            "--recover",
            "true",
        ]

        completed = subprocess.run(command, text=True, capture_output=True, check=False)
        if completed.returncode != 0:
            raise RuntimeError(
                "RECmd extraction failed for "
                f"{job.hive_path} branch {job.branch!r}: {completed.stderr or completed.stdout}"
            )

    return len(jobs)
