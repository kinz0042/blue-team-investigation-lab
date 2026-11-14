# Remote access investigation lab

An offline SOC pipeline that correlates Windows logon failures, successful remote access, encoded PowerShell and process-linked network connections. Built and tested on Linux using Python's standard library.

## Run
```bash
python3 investigate.py
python3 -m unittest discover -s tests -v
```

Open reports/index.html locally for the investigation view. Review reports/findings.json for evidence IDs and reports/triage.md for analyst decisions.

All bundled events are synthetic. The encoded command represents harmless whoami text. The analyzer reads telemetry without executing its commands.

## Correlation

Five type 10 failures within ten minutes before a success must share destination host, domain, user and source IP. A normalized logon event maps the exact successful Security record, timestamp, host and user to a session. Encoded PowerShell must share that host/session and occur within fifteen minutes. A network event must share the process GUID.

Two findings result from the sample. One receives high priority because execution and a linked connection accompany the authentication sequence. A connection does not establish exfiltration or command-and-control. The separate case notes provide the user denial and training context used in triage.

## Data contract

Authentication CSV columns are timestamp, record_id, event_id, computer, domain, user, src_ip, logon_type. Times need an offset. Records must come from one continuous Security capture per host. Separate captures after log clearing.

Endpoint JSONL fields are id, timestamp, host, session, kind. Kinds are logon, process, network. Logon adds security_record and user. Process adds image, command_line and process_guid. Network adds process_guid, destination and destination_port. Endpoint IDs must be unique per host.

Inputs are normalized telemetry. Raw EVTX and Sysmon XML require conversion. Correct session mapping and comparable endpoint clocks are collector responsibilities. Missing mappings appear in findings and prevent endpoint attribution. Input SHA256 hashes accompany generated reports.

## Validation and limits

18 tests pass on Linux. Tests exercise duplicate suppression, conflict rejection, UTC conversion, time boundaries, host/source/domain isolation, session separation, process GUID association and HTML escaping.

This finite offline analyzer regenerates reports per run. Use a separate output directory for each evidence set. It has no live ingestion or automatic containment. The matcher recognizes explicit -enc and -EncodedCommand tokens. Obfuscated variants, distributed spraying and missing telemetry require additional detections. Production precision and recall remain unmeasured.

## Portfolio use

A reviewer can reproduce the analysis and trace every priority decision to event IDs. Be ready to explain why a shared IP cannot establish process/session identity, why authorized training can match a rule and how missing telemetry affects confidence.

Developed with AI assistance and executed in a Linux environment. See RESEARCH.md and PLAYBOOK.md.
