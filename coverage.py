"""Inventory a public Windows capture without asserting an attack verdict."""
import hashlib
import json
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
archive = ROOT / "data/public/capture.zip"
with zipfile.ZipFile(archive) as capture:
    members = [member for member in capture.infolist() if member.filename.endswith(".json")]
    if len(members) != 1 or members[0].file_size > 10_000_000:
        raise ValueError("expected one JSON capture under 10 MB")
    events = [json.loads(line) for line in capture.read(members[0]).decode().splitlines() if line.strip()]
counts = Counter((str(event.get("Channel")), int(event["EventID"])) for event in events)
report = {
    "capture_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
    "event_count": len(events),
    "counts": [{"channel": channel, "event_id": event_id, "count": count}
               for (channel, event_id), count in sorted(counts.items())],
    "coverage": {
        "failed_logons_4625": counts[("Security", 4625)],
        "successful_logons_4624": counts[("Security", 4624)],
        "sysmon_process_1": counts[("Microsoft-Windows-Sysmon/Operational", 1)],
        "sysmon_network_3": counts[("Microsoft-Windows-Sysmon/Operational", 3)]
    },
    "verdict": "Insufficient telemetry to evaluate the remote-access correlation. No compromise verdict.",
}
destination = ROOT / "reports/public-coverage.json"
destination.write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))
