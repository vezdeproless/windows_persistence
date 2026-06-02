from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from persist_detector.hunt import build_hunt_records, write_hunt_report


class HuntTests(unittest.TestCase):
    def test_builds_frequency_records_and_marks_suspicious_paths(self) -> None:
        records = [
            {
                "@timestamp": "2026-05-19T09:00:00",
                "event.dataset": "windows.registry.persistence",
                "host.name": "WIN10-LAB",
                "reg.key.path": "System\\ControlSet001\\Services\\GoodSvc",
                "file.name": "ImagePath",
                "file.path": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
                "threat.technique.id": "T1543/003",
            },
            {
                "@timestamp": "2026-05-19T09:01:00",
                "event.dataset": "windows.registry.persistence",
                "host.name": "WIN10-LAB",
                "reg.key.path": "System\\ControlSet001\\Services\\OtherSvc",
                "file.name": "ImagePath",
                "file.path": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
                "threat.technique.id": "T1543/003",
            },
            {
                "@timestamp": "2026-05-19T09:02:00",
                "event.dataset": "windows.registry.persistence",
                "host.name": "WIN10-LAB",
                "reg.key.path": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "file.name": "Updater",
                "file.path": "C:\\Users\\Public\\evil.exe",
                "threat.technique.id": "T1547/001",
            },
        ]

        hunt_records = build_hunt_records(records, rare_threshold=1, generated_at="2026-05-19T10:00:00")
        path_records = [record for record in hunt_records if record["hunt.kind"] == "executable_path"]
        evil_record = next(record for record in path_records if record["file.path"] == "C:\\Users\\Public\\evil.exe")
        svchost_record = next(
            record for record in path_records if record["file.path"] == "C:\\Windows\\System32\\svchost.exe -k netsvcs"
        )

        self.assertEqual(evil_record["frequency.count"], 1)
        self.assertEqual(evil_record["frequency.rarity"], "unique")
        self.assertEqual(evil_record["anomaly.executable.path"], "true")
        self.assertEqual(evil_record["hunt.suspicious"], "true")
        self.assertIn("user_public_path", evil_record["anomaly.executable.reason"])
        self.assertEqual(svchost_record["frequency.count"], 2)
        self.assertEqual(svchost_record["frequency.rarity"], "common")

    def test_writes_hunt_report_ndjson(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            registry_json = root / "Registry.json"
            registry_json.write_text(
                json.dumps(
                    {
                        "@timestamp": "2026-05-19T09:02:00",
                        "event.dataset": "windows.registry.persistence",
                        "host.name": "WIN11-LAB",
                        "reg.key.path": "Software\\Microsoft\\Netsh",
                        "file.name": "NetshHelper",
                        "file.path": "C:\\AtomicRedTeam\\atomics\\T1546.007\\bin\\NetshHelper.dll",
                        "threat.technique.id": "T1546/007",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            output = root / "PersistenceHunt.json"
            count = write_hunt_report([registry_json], output)
            lines = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]

            self.assertEqual(count, 3)
            self.assertEqual(len(lines), 3)
            self.assertTrue(all(line["event.dataset"] == "windows.registry.persistence.hunt" for line in lines))
            self.assertTrue(any(line["hunt.kind"] == "registry_location" for line in lines))


if __name__ == "__main__":
    unittest.main()
