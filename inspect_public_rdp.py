"""Inventory original OTRF evidence and preserve Task Manager/LSASS access records."""
import hashlib
import json
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
archive = ROOT / "data/public/rdp-capture.zip"
with zipfile.ZipFile(archive) as capture:
    members = capture.infolist()
    if len(members) != 1 or members[0].file_size > 10_000_000:
        raise ValueError("Expected one capture under 10 MB")
    events = [json.loads(line) for line in capture.read(members[0]).decode().splitlines() if line.strip()]
counts = Counter((str(e.get("Channel")).casefold(), int(e["EventID"])) for e in events)
access = [event for event in events if event.get("EventID") == 10
          and str(event.get("SourceImage", "")).casefold().endswith("\\taskmgr.exe")
          and str(event.get("TargetImage", "")).casefold().endswith("\\lsass.exe")]
fields = ["Hostname", "RecordNumber", "UtcTime", "SourceImage", "TargetImage",
          "SourceProcessGUID", "TargetProcessGUID", "GrantedAccess"]
report = {
    "source_url": "https://raw.githubusercontent.com/OTRF/Security-Datasets/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/datasets/atomic/windows/credential_access/host/rdp_interactive_taskmanager_lsass_dump.zip",
    "source_commit": "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87",
    "license": "data/public/LICENSE.txt",
    "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
    "event_count": len(events),
    "coverage": {
        "failed_logons": counts["security", 4625],
        "successful_logons": counts["security", 4624],
        "process_events": counts["microsoft-windows-sysmon/operational", 1],
        "network_events": counts["microsoft-windows-sysmon/operational", 3],
    },
    "taskmgr_lsass_access": [{field: event.get(field) for field in fields} for event in access],
    "assessment": "Task Manager accessed LSASS in the source capture. Process access alone does not prove successful credential dumping. No failed logons are present, so this capture cannot exercise the repeated-failures rule.",
}
(ROOT / "reports/rdp-public-coverage.json").write_text(json.dumps(report, indent=2)+"\n")
print(json.dumps({"events": len(events), "taskmgr_lsass_access_records": len(access)}))
