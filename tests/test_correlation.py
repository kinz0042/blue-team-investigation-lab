import json
import tempfile
import unittest
from pathlib import Path
from investigate import ROOT, investigate, read_telemetry, write_report

class CorrelationTests(unittest.TestCase):
    def run_events(self, transform):
        events = read_telemetry(ROOT / "data/telemetry.jsonl")
        events = transform(events)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, "telemetry.jsonl")
            path.write_text("\n".join(json.dumps(e) for e in events))
            return investigate(ROOT / "data/logons.csv", path)

    def test_expected_evidence(self):
        findings = self.run_events(lambda e:e)["findings"]
        self.assertEqual([f["priority"] for f in findings], ["high", "medium"])
        self.assertEqual(findings[0]["encoded_process_ids"], ["p41"])
        self.assertEqual(findings[0]["linked_network_ids"], ["n42"])

    def test_wrong_session_does_not_correlate(self):
        def change(events):
            for event in events:
                if event["id"] == "p41":
                    event["session"] = "unrelated"
            return events
        self.assertEqual(self.run_events(change)["findings"][0]["priority"], "medium")

    def test_process_guid_required_for_network_link(self):
        def change(events):
            for event in events:
                if event["id"] == "n42":
                    event["process_guid"] = "other"
            return events
        self.assertFalse(self.run_events(change)["findings"][0]["linked_network_ids"])

    def test_time_window_excludes_late_execution(self):
        def change(events):
            for event in events:
                if event["id"] == "p41":
                    event["timestamp"] = "2026-11-12T10:00:00Z"
            return events
        self.assertEqual(self.run_events(change)["findings"][0]["priority"], "medium")

    def test_missing_mapping_is_visible(self):
        findings=self.run_events(lambda es:[e for e in es if e["kind"]!="logon"])["findings"]
        self.assertFalse(findings[0]["session_mapping_available"])
        self.assertFalse(findings[0]["timeline"])

    def test_output_escapes_untrusted_commands(self):
        result=self.run_events(lambda e:e)
        result["findings"][0]["timeline"][1]["command_line"]="<script>alert(1)</script>"
        with tempfile.TemporaryDirectory() as folder:
            write_report(result, Path(folder), [ROOT/"data/logons.csv"])
            self.assertIn("&lt;script&gt;", Path(folder,"index.html").read_text())
