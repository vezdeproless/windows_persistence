from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from persist_detector.extract import ExtractionJob, build_recmd_command


class ExtractTests(unittest.TestCase):
    def test_recmd_command_uses_short_file_option_supported_by_recmd(self) -> None:
        job = ExtractionJob(
            hive_kind="SYSTEM",
            hive_path=Path("/uploads/HOST/Reg/SYSTEM"),
            branch="ControlSet001\\Services",
            output_name="SYSTEM-ControlSet001%5CServices.json",
        )

        command = build_recmd_command(Path("/usr/local/bin/recmd"), job, Path("/uploads/HOST/processed/extracted"))

        self.assertEqual(command[1], "-f")
        self.assertNotIn("--f", command)
        self.assertIn("--kn", command)
        self.assertIn("--json", command)
        self.assertIn("--jsonf", command)


if __name__ == "__main__":
    unittest.main()
