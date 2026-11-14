"""Correlate original public Sysmon process, access and dump-file evidence."""
import json
import zipfile
from datetime import datetime
from pathlib import Path
ROOT = Path(__file__).resolve().parent


def event_time(event):
    return datetime.strptime(event["UtcTime"], "%Y-%m-%d %H:%M:%S.%f")


def correlate(events):
    processes = {(e["Hostname"].casefold(), e["ProcessGuid"].casefold()): e
                 for e in events if e.get("EventID") == 1 and e.get("ProcessGuid")}
    findings = []
    for file in events:
        if file.get("EventID") != 11 or not str(file.get("TargetFilename", "")).casefold().endswith("\\lsass.dmp"):
            continue
        identity = (file["Hostname"].casefold(), file["ProcessGuid"].casefold())
        process = processes.get(identity)
        if not process or event_time(process) > event_time(file):
            continue
        accesses = [e for e in events if e.get("EventID") == 10
                    and e["Hostname"].casefold() == identity[0]
                    and e.get("SourceProcessGUID", "").casefold() == identity[1]
                    and str(e.get("TargetImage", "")).casefold().endswith("\\lsass.exe")
                    and event_time(process) <= event_time(e) <= event_time(file)]
        if accesses:
            findings.append({
                "host": file["Hostname"], "user": process.get("User"),
                "process_guid": file["ProcessGuid"], "process_record": process["RecordNumber"],
                "process_utc": process["UtcTime"], "image": process["Image"],
                "access_records": [e["RecordNumber"] for e in accesses],
                "file_record": file["RecordNumber"], "file_utc": file["UtcTime"],
                "file_path": file["TargetFilename"],
                "assessment": "LSASS access followed by creation of an LSASS-named dump artifact by the same process. Dump contents and credential extraction were not examined.",
            })
    return findings


if __name__ == "__main__":
    with zipfile.ZipFile(ROOT / "data/public/rdp-capture.zip") as archive:
        events = [json.loads(line) for line in archive.read(archive.namelist()[0]).decode().splitlines() if line.strip()]
    findings = correlate(events)
    (ROOT / "reports/public-rdp-investigation.json").write_text(json.dumps(findings, indent=2)+"\n")
    print(json.dumps(findings, indent=2))
