from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from persist_detector.normalize import normalize_directory, normalize_recmd_json


class NormalizeTests(unittest.TestCase):
    def test_flattens_values_filters_noise_and_formats_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            input_dir = Path(temp_dir)
            source = input_dir / "SOFTWARE-Microsoft%5CWindows%5CCurrentVersion%5CRun.json"
            source.write_text(
                json.dumps(
                    {
                        "KeyPath": "ROOT\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "KeyName": "Run",
                        "LastWriteTime": "2026-05-19 12:34:56.1234567",
                        "Values": [
                            {
                                "ValueName": "Updater",
                                "ValueType": "RegSz",
                                "ValueData": " C:\\Users\\Public\\updater.exe ",
                            },
                            {"ValueName": "Empty", "ValueType": "RegSz", "ValueData": ""},
                            {"ValueName": "Numeric", "ValueType": "RegDword", "ValueData": "1"},
                            {"ValueName": "NoType", "ValueData": "C:\\bad.exe"},
                        ],
                        "SubKeys": [
                            {
                                "KeyPath": "ROOT\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                                "KeyName": "Winlogon",
                                "LastWriteTime": "2026-05-19T01:00:00+00:00",
                                "Values": [
                                    {
                                        "ValueName": "Shell",
                                        "ValueType": "RegSz",
                                        "ValueData": "explorer.exe, C:\\Temp\\evil.exe",
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            output = input_dir / "Registry.json"
            count = normalize_directory(input_dir, output, host_name="WIN10-LAB")

            self.assertEqual(count, 2)
            lines = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(lines[0]["@timestamp"], "2026-05-19T09:34:56")
            self.assertEqual(lines[0]["host.name"], "WIN10-LAB")
            self.assertEqual(lines[0]["reg.key.path"], "Software\\Microsoft\\Windows\\CurrentVersion\\Run")
            self.assertEqual(lines[0]["reg.key.name"], "Run")
            self.assertEqual(lines[0]["file.name"], "Updater")
            self.assertEqual(lines[0]["file.path"], "C:\\Users\\Public\\updater.exe")
            self.assertEqual(lines[0]["threat.technique.id"], "T1547/001")
            self.assertEqual(lines[1]["reg.key.name"], "Winlogon")

    def test_user_hive_root_is_renamed_with_username(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "NTUSER-alice-Environment.json"
            source.write_text(
                json.dumps(
                    {
                        "KeyPath": "ROOT\\Environment",
                        "KeyName": "Environment",
                        "LastWriteTime": "2026-05-19T03:00:00Z",
                        "Values": [
                            {
                                "ValueName": "UserInitMprLogonScript",
                                "ValueType": "RegSz",
                                "ValueData": "\\\\fileserver\\netlogon\\login.bat",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            records = normalize_recmd_json(source)

            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["user.name"], "alice")
            self.assertEqual(records[0]["reg.key.path"], "NTUSER.DAT-alice\\Environment")
            self.assertIn("T1037/001", records[0]["threat.technique.id"])


if __name__ == "__main__":
    unittest.main()
