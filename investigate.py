"""Correlate Windows authentication, process and network evidence offline."""
import argparse
import hashlib
import html
import json
from datetime import datetime, timedelta
from pathlib import Path
from auth import analyze

ROOT = Path(__file__).resolve().parent


def stamp(value):
    moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        raise ValueError("UTC offset required")
    return moment


def read_telemetry(path):
    events = {}
    for line, text in enumerate(path.read_text().splitlines(), 1):
        try:
            item = json.loads(text)
            for field in ("id", "timestamp", "host", "session", "kind"):
                if not item.get(field):
                    raise ValueError("missing " + field)
            stamp(item["timestamp"])
            if item["kind"] not in {"logon", "process", "network"}:
                raise ValueError("unknown kind")
            identity = (item["host"].casefold(), item["id"])
            if identity in events and events[identity] != item:
                raise ValueError("conflicting event ID")
            events[identity] = item
        except (ValueError, TypeError, KeyError) as error:
            raise ValueError(f"{path.name} line {line}: {error}") from error
    return sorted(events.values(), key=lambda e: (stamp(e["timestamp"]), e["id"]))


def investigate(auth_file, telemetry_file):
    result = analyze(auth_file)
    events = read_telemetry(telemetry_file)
    findings = []
    for alert in result["alerts"]:
        start = stamp(alert["success_utc"])
        # Session identity must come from the successful Security event.
        sessions = [e for e in events if e["kind"] == "logon"
                    and e["host"].casefold() == alert["computer"]
                    and e.get("security_record") == alert["success_record_id"]
                    and stamp(e["timestamp"]) == start
                    and e.get("user", "").casefold() == alert["domain"] + "\\" + alert["user"]]
        if len(sessions) > 1:
            raise ValueError("ambiguous Security-to-session mapping")
        related = []
        if sessions:
            session = sessions[0]["session"]
            related = [e for e in events if e["host"].casefold() == alert["computer"]
                       and e["session"] == session
                       and start <= stamp(e["timestamp"]) <= start + timedelta(minutes=15)]
        processes = [e for e in related if e["kind"] == "process"]
        encoded = [e for e in processes
                   if e.get("image", "").replace("/", "\\").split("\\")[-1].casefold()
                   in {"powershell.exe", "pwsh.exe"}
                   and any(token.casefold() in {"-enc", "-encodedcommand"}
                           for token in e.get("command_line", "").split())]
        process_starts = {e["process_guid"]: stamp(e["timestamp"])
                          for e in encoded if e.get("process_guid")}
        connections = [e for e in related if e["kind"] == "network"
                       and e.get("process_guid") in process_starts
                       and stamp(e["timestamp"]) >= process_starts[e["process_guid"]]]
        findings.append({
            "authentication": alert,
            "priority": "high" if encoded and connections else "medium",
            "reason": "Repeated failures, successful remote logon, encoded PowerShell and a linked connection"
                      if encoded and connections else "Repeated failures followed by a successful remote logon",
            "session_mapping_available": bool(sessions),
            "encoded_process_ids": [e["id"] for e in encoded],
            "linked_network_ids": [e["id"] for e in connections],
            "timeline": related,
        })
    return {"authentication_quality": {k: v for k, v in result.items() if k != "alerts"},
            "findings": findings}


def write_report(result, output, inputs):
    output.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(result, indent=2) + "\n"
    (output / "findings.json").write_text(payload)
    sections = []
    for finding in result["findings"]:
        a = finding["authentication"]
        rows = "".join("<tr>" + "".join("<td>" + html.escape(str(e.get(k, ""))) + "</td>"
                       for k in ("timestamp", "id", "kind", "command_line", "destination")) + "</tr>"
                       for e in finding["timeline"])
        sections.append("<section><h2>" + html.escape(a["domain"] + "\\" + a["user"])
                        + "</h2><p>" + html.escape(finding["priority"] + " — " + finding["reason"])
                        + "</p><p>Host " + html.escape(a["computer"]) + " · "
                        + str(a["failures"]) + " failures · success record "
                        + str(a["success_record_id"]) + "</p><table><thead><tr>"
                        + "<th>UTC time</th><th>Evidence</th><th>Type</th><th>Command</th><th>Destination</th>"
                        + "</tr></thead><tbody>" + rows + "</tbody></table></section>")
    (output / "index.html").write_text(
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
        '<title>Remote access investigation</title><style>body{font:16px system-ui;background:#101820;color:#e4edf4;'
        'max-width:1100px;margin:40px auto;padding:20px}section{padding:20px;background:#1c2b38;margin:20px 0}'
        'table{border-collapse:collapse;width:100%}td,th{padding:10px;text-align:left;border-bottom:1px solid #426078;'
        'overflow-wrap:anywhere}h1,h2{color:#84d9cf}</style><h1>Remote access investigation</h1>'
        '<p>Simulated evidence · Windows Security and normalized Sysmon · Offline Linux analysis</p>'
        + "".join(sections) + '</html>')
    manifest = {str(path.name): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}
    (output / "input-sha256.json").write_text(json.dumps(manifest, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--auth", type=Path, default=ROOT / "data/logons.csv")
    parser.add_argument("--telemetry", type=Path, default=ROOT / "data/telemetry.jsonl")
    parser.add_argument("--output", type=Path, default=ROOT / "reports")
    args = parser.parse_args()
    try:
        result = investigate(args.auth, args.telemetry)
        write_report(result, args.output, [args.auth, args.telemetry])
    except (OSError, ValueError) as error:
        parser.exit(2, f"Investigation failed: {error}\n")
    print(json.dumps({"findings": len(result["findings"]),
                      "high_priority": sum(f["priority"] == "high" for f in result["findings"]) }))


if __name__ == "__main__":
    main()
