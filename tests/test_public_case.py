import copy
import json
import unittest
import zipfile
from investigate_public_rdp import ROOT, correlate

class PublicCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with zipfile.ZipFile(ROOT / "data/public/rdp-capture.zip") as archive:
            cls.events = [json.loads(line) for line in archive.read(archive.namelist()[0]).decode().splitlines() if line.strip()]

    def test_record_linkage(self):
        finding = correlate(self.events)
        self.assertEqual(len(finding), 1)
        self.assertEqual(finding[0]["process_record"], 3405712)
        self.assertEqual(finding[0]["file_record"], 3407010)
        self.assertEqual(len(finding[0]["access_records"]), 6)

    def test_other_process_cannot_inherit_access(self):
        events = copy.deepcopy(self.events)
        for event in events:
            if event.get("RecordNumber") == 3407010:
                event["ProcessGuid"] = "{b34bc01c-b7f3-5f69-dd02-000000000900}"
        self.assertFalse(correlate(events))

    def test_wrong_destination_host(self):
        events = copy.deepcopy(self.events)
        for event in events:
            if event.get("RecordNumber") == 3407010:
                event["Hostname"] = "OTHER"
        self.assertFalse(correlate(events))

    def test_file_before_access(self):
        events = copy.deepcopy(self.events)
        for event in events:
            if event.get("RecordNumber") == 3407010:
                event["UtcTime"] = "2020-09-22 08:38:11.700"
        self.assertFalse(correlate(events))
