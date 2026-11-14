# Splunk integration status

The search in this directory is an unexecuted draft for the project's normalized endpoint JSONL schema. It covers encoded PowerShell only. The full authentication/session/network correlation remains implemented and tested in Python.

To validate it, ingest data/telemetry.jsonl with JSON field extraction, sourcetype bt:endpoint, index blue_team and timestamp field timestamp. Do not infer production correctness from this draft. Expected process candidates are p41 and the distractor p99. Session correlation must remove p99 from the a.okoro incident.

Splunk runtime deployment, executed SPL tests and a Splunk dashboard remain pending. The Linux environment has no Splunk installation or authenticated download session.
