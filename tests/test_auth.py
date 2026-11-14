import csv
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from auth import SAMPLE, analyze

BASE = datetime(2026, 11, 12, 9, tzinfo=timezone.utc)
FIELDS = ["timestamp", "record_id", "event_id", "computer", "domain", "user", "src_ip", "logon_type"]


def row(seconds, record, kind=4625, **changes):
    stamp = (BASE + timedelta(seconds=seconds)).isoformat()
    values = dict(zip(FIELDS, [stamp, record, kind, "PC01", "LAB", "analyst", "192.0.2.2", 10]))
    return {**values, **changes}


def failures(count=5):
    return [row(i * 30, i + 1) for i in range(count)]


class DetectionTests(unittest.TestCase):
    def run_rows(self, rows):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, "records.csv")
            with path.open("w", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=FIELDS)
                writer.writeheader()
                writer.writerows(rows)
            return analyze(path)

    def test_included_evidence(self):
        result = analyze(SAMPLE)
        self.assertEqual([a["success_record_id"] for a in result["alerts"]], [2007, 1008])

    def test_boundary_and_input_order(self):
        result = self.run_rows([row(600, 6, 4624), *reversed(failures())])
        self.assertEqual(result["alerts"][0]["failure_record_ids"], [1, 2, 3, 4, 5])

    def test_oldest_failure_expires(self):
        self.assertFalse(self.run_rows(failures() + [row(601, 6, 4624)])["alerts"])

    def test_repeated_forwarding_cannot_inflate_count(self):
        result = self.run_rows(failures(4) + [row(0, 1), row(130, 6, 4624)])
        self.assertEqual(result["duplicates_removed"], 1)
        self.assertFalse(result["alerts"])

    def test_conflicting_record_rejected(self):
        with self.assertRaisesRegex(ValueError, "conflicting records"):
            self.run_rows([row(0, 1), row(1, 1)])

    def test_success_consumes_failures_even_below_threshold(self):
        data = failures(3) + [row(80, 4, 4624), row(100, 5), row(101, 6), row(102, 7, 4624)]
        self.assertFalse(self.run_rows(data)["alerts"])

    def test_plain_failures_do_not_match(self):
        self.assertFalse(self.run_rows(failures(8))["alerts"])

    def test_group_and_logon_type_must_match(self):
        for changes in ({"domain": "SALES"}, {"user": "other"}, {"computer": "PC02"},
                        {"src_ip": "192.0.2.3"}, {"logon_type": 3}):
            with self.subTest(changes=changes):
                self.assertFalse(self.run_rows(failures() + [row(200, 6, 4624, **changes)])["alerts"])

    def test_missing_source_accounted_for(self):
        result = self.run_rows(failures() + [row(150, 6, 4624, src_ip="-")])
        self.assertEqual(result["eligible_events_missing_source"], 1)
        self.assertFalse(result["alerts"])

    def test_mapped_address_case_and_local_time(self):
        success = row(150, 6, 4624, domain="lab", user="ANALYST", src_ip="::ffff:192.0.2.2",
                      timestamp="2026-11-12T10:02:30+01:00")
        self.assertEqual(self.run_rows(failures() + [success])["alerts"][0]["failures"], 5)

    def test_same_timestamp_uses_host_record_order(self):
        data = [row(0, i) for i in range(1, 6)] + [row(0, 6, 4624)]
        self.assertEqual(self.run_rows(reversed(data))["alerts"][0]["failures"], 5)

    def test_invalid_input_reports_line(self):
        with self.assertRaisesRegex(ValueError, "line 2"):
            self.run_rows([row(0, 1, timestamp="bad")])
