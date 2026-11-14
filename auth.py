"""Find remote-interactive successes preceded by repeated logon failures."""
import argparse
import csv
import json
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import IPv6Address, ip_address
from pathlib import Path

REQUIRED = {"timestamp", "record_id", "event_id", "computer", "domain",
            "user", "src_ip", "logon_type"}
WINDOW = timedelta(minutes=10)
MIN_FAILURES = 5
SAMPLE = Path(__file__).resolve().parent / "data" / "logons.csv"


@dataclass(frozen=True)
class Event:
    time: datetime
    record: int
    kind: int
    computer: str
    domain: str
    user: str
    source: str
    logon_type: int

    @property
    def group(self):
        return (self.computer, self.domain, self.user, self.source)


def parse_row(row):
    stamp = row["timestamp"].strip()
    if stamp.endswith("Z"):
        stamp = stamp[:-1] + "+00:00"
    moment = datetime.fromisoformat(stamp)
    if moment.tzinfo is None:
        raise ValueError("timestamp needs a UTC offset or Z")
    parts = [row[name].strip().casefold() for name in ("computer", "domain", "user")]
    if any(part in {"", "-"} for part in parts):
        raise ValueError("missing computer, domain or user")
    source = row["src_ip"].strip()
    if source in {"", "-"}:
        source = ""
    else:
        address = ip_address(source)
        if isinstance(address, IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        source = str(address)
    record = int(row["record_id"])
    if record <= 0:
        raise ValueError("record_id must be positive")
    return Event(moment.astimezone(timezone.utc), record, int(row["event_id"]),
                 *parts, source, int(row["logon_type"]))


def read_events(path):
    unique = {}
    duplicates = 0
    with path.open(newline="", encoding="utf-8-sig") as handle:
        rows = csv.DictReader(handle)
        missing = REQUIRED.difference(rows.fieldnames or ())
        if missing:
            raise ValueError("missing columns: " + ", ".join(sorted(missing)))
        for row in rows:
            try:
                if None in row or any(row[name] is None for name in REQUIRED):
                    raise ValueError("unexpected number of fields")
                event = parse_row(row)
                identity = (event.computer, event.record)
                if identity in unique:
                    if unique[identity] != event:
                        raise ValueError("conflicting records for the same computer and record_id")
                    duplicates += 1
                else:
                    unique[identity] = event
            except ValueError as error:
                raise ValueError(f"line {rows.line_num}: {error}") from error
    return sorted(unique.values(), key=lambda e: (e.time, e.record)), duplicates


def utc_string(value):
    return value.isoformat().replace("+00:00", "Z")


def analyze(path):
    events, duplicates = read_events(path)
    pending = defaultdict(deque)
    alerts = []
    missing_source = 0
    for event in events:
        if event.kind not in {4624, 4625} or event.logon_type != 10:
            continue
        if not event.source:
            missing_source += 1
            continue
        failures = pending[event.group]
        while failures and event.time - failures[0].time > WINDOW:
            failures.popleft()
        if event.kind == 4625:
            failures.append(event)
            continue
        if len(failures) >= MIN_FAILURES:
            alerts.append({
                "computer": event.computer, "domain": event.domain,
                "user": event.user, "src_ip": event.source,
                "first_failure_utc": utc_string(failures[0].time),
                "last_failure_utc": utc_string(failures[-1].time),
                "success_utc": utc_string(event.time), "failures": len(failures),
                "failure_record_ids": [item.record for item in failures],
                "success_record_id": event.record,
            })
        del pending[event.group]
    return {"unique_events": len(events), "duplicates_removed": duplicates,
            "eligible_events_missing_source": missing_source, "alerts": alerts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_file", type=Path, nargs="?", default=SAMPLE)
    args = parser.parse_args()
    try:
        result = analyze(args.csv_file)
    except (OSError, ValueError, csv.Error) as error:
        parser.exit(2, f"Input error: {error}\n")
    json.dump(result, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
