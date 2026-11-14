import os
import base64
import csv
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

project = Path(__file__).resolve().parents[2]
password = Path(os.environ["SPLUNK_PASSWORD_FILE"]).read_text().strip()
authorization = "Basic " + base64.b64encode(("admin:" + password).encode()).decode()
context = ssl._create_unverified_context()

def request(path, fields=None, raw=None):
    body = raw if raw is not None else urllib.parse.urlencode(fields or {}).encode()
    req = urllib.request.Request("https://127.0.0.1:8089" + path, data=body)
    req.add_header("Authorization", authorization)
    return urllib.request.urlopen(req, context=context, timeout=60).read().decode()

def search(query):
    text = request("/services/search/jobs/export", {"search": query, "output_mode": "json"})
    records = [json.loads(line) for line in text.splitlines() if line.strip()]
    errors = [message for record in records for message in record.get("messages", [])
              if message.get("type") in {"ERROR", "FATAL"}]
    if errors:
        raise RuntimeError(errors)
    return [record["result"] for record in records if "result" in record]

try:
    request("/services/data/indexes", {"name": "blue_team"})
except urllib.error.HTTPError as error:
    if error.code != 409:
        raise
# Explicit ingestion tags keep each replay separate, including reruns.
run_id = str(time.time_ns())
events = [json.loads(line) for line in (project / "data/telemetry.jsonl").read_text().splitlines()]
for event in events:
    event["capture_type"] = "synthetic_endpoint"
    event["validation_run"] = run_id
request("/services/receivers/simple?index=blue_team&sourcetype=bt:endpoint", raw=("\n".join(json.dumps(e) for e in events)+"\n").encode())
auth = list(csv.DictReader((project / "data/logons.csv").open()))
for event in auth:
    event["capture_type"] = "synthetic_auth"
    event["validation_run"] = run_id
request("/services/receivers/simple?index=blue_team&sourcetype=bt:auth", raw=("\n".join(json.dumps(e) for e in auth)+"\n").encode())
base = 'search index=blue_team validation_run="' + run_id + '" earliest=0 latest=now | fields _raw _time sourcetype | fields - host | spath'
for attempt in range(30):
    counts = search(base + " | stats count")
    if counts and int(counts[0]["count"]) == len(events) + len(auth):
        break
    time.sleep(1)
else:
    raise RuntimeError("ingestion count mismatch: " + str(counts))

candidate = base + ' | search sourcetype="bt:endpoint" kind=process | regex command_line="(?i)(^|\\s)-(enc|encodedcommand)(\\s|$)" | table id host session process_guid command_line'
candidates = search(candidate)
assert sorted(e["id"] for e in candidates) == ["p41", "p99"], candidates
# Correlate the session and process GUID using event time, preserving process-before-network ordering.
chain = base + """ | search sourcetype="bt:endpoint"
| eval event_time=strptime(timestamp,"%Y-%m-%dT%H:%M:%SZ")
| eval encoded=if(kind="process" AND match(lower(image),"(^|[^a-z0-9_.-])(powershell|pwsh)[.]exe$") AND match(command_line,"(?i)(^|\\s)-(enc|encodedcommand)(\\s|$)"),1,0)
| eventstats min(eval(if(encoded=1,event_time,null()))) as process_start by host session process_guid
| eval valid_network=if(kind="network" AND event_time>=process_start,1,0)
| eventstats values(eval(if(valid_network=1,id,null()))) as network_evidence by host session process_guid
| eventstats values(eval(if(kind="logon",security_record,null()))) as successful_record by host session
| where encoded=1 AND isnotnull(network_evidence) AND isnotnull(successful_record)
| table id host session successful_record network_evidence"""
chain = chain.replace('| eval encoded=', '''| eventstats min(eval(if(kind="logon",event_time,null()))) as logon_start by host session
| where event_time>=logon_start AND event_time<=logon_start+900
| eval encoded=''')
chains = search(chain)
assert [e["id"] for e in chains] == ["p41"], chains
auth_query = base + """
| search sourcetype="bt:auth" logon_type=10 (event_id=4624 OR event_id=4625)
| eval _time=strptime(timestamp,"%Y-%m-%dT%H:%M:%SZ"), record_id=tonumber(record_id), event_id=tonumber(event_id)
| eval computer=lower(computer), domain=lower(domain), user=lower(user)
| dedup computer record_id
| where src_ip!="" AND src_ip!="-"
| sort 0 +_time +record_id
| streamstats current=f count(eval(event_id=4624)) as previous_successes by computer domain user src_ip
| fillnull value=0 previous_successes
| streamstats time_window=10m count(eval(event_id=4625)) as failures by computer domain user src_ip previous_successes
| where event_id=4624 AND failures>=5
| table computer domain user src_ip record_id failures"""
auth_findings = search(auth_query)
assert sorted(int(e["record_id"]) for e in auth_findings)==[1008,2007], auth_findings
for finding in auth_findings:
    finding["priority"] = "high" if any(int(c["successful_record"])==int(finding["record_id"]) and c["host"].casefold()==finding["computer"] for c in chains) else "medium"

negative_cases = [
    ("wrong_executable", 'eval image=if(id="p41","C:/Windows/notepad.exe",image)'),
    ("wrong_network_guid", 'eval process_guid=if(id="n42","{OTHER}",process_guid)'),
    ("wrong_network_host", 'eval host=if(id="n42","OTHER-HOST",host)'),
    ("wrong_network_session", 'eval session=if(id="n42","0xOTHER",session)'),
    ("connection_before_process", 'eval timestamp=if(id="n42","2026-11-12T09:05:03Z",timestamp)'),
    ("process_after_window", 'eval timestamp=if(id="p41","2026-11-12T09:30:00Z",timestamp)'),
    ("missing_logon", 'where kind!="logon"'),
]
negative_results = []
for name, mutation in negative_cases:
    rows = search(chain.replace(base, base+" | "+mutation, 1))
    if rows:
        raise RuntimeError("False chain in "+name+": "+str(rows))
    negative_results.append({"case": name, "expected_chains": 0, "actual_chains": len(rows), "passed": True})
(project / "reports/splunk-negative-tests.json").write_text(json.dumps(negative_results, indent=2)+"\n")
out = project / "reports/splunk-validation.json"
out.write_text(json.dumps({
    "splunk_version": "10.6.1.1", "run_id": run_id,
    "ingested_synthetic_endpoint": len(events), "ingested_synthetic_auth": len(auth),
    "encoded_candidates": candidates, "authentication_findings": auth_findings, "session_process_network_chain": chains,
    "limits": "Validated on synthetic replay only. Production accuracy and complete real-capture chain remain unmeasured."
}, indent=2)+"\n")
(project / "detections/splunk/validated-session-chain.spl").write_text(chain.replace(run_id, '<VALIDATION_RUN>')+"\n")
(project / "detections/splunk/validated-authentication.spl").write_text(auth_query.replace(run_id, '<VALIDATION_RUN>')+"\n")

import html
dashboard = '<dashboard version="1.1"><label>Blue Team Evidence Validation</label><description>Synthetic replay. Authentication and endpoint correlation validation.</description><row><panel><table><title>Repeated failures followed by success</title><search><query>' + html.escape(auth_query) + '</query><earliest>0</earliest><latest>now</latest></search></table></panel></row><row><panel><table><title>Session and process-linked network evidence</title><search><query>' + html.escape(chain) + '</query><earliest>0</earliest><latest>now</latest></search></table></panel></row></dashboard>'
(project / "detections/splunk/dashboard.xml").write_text(dashboard+"\n")
try:
    request("/servicesNS/admin/search/data/ui/views", {"name":"blue_team_evidence", "eai:data":dashboard})
except urllib.error.HTTPError as error:
    if error.code!=409:
        raise
    request("/servicesNS/admin/search/data/ui/views/blue_team_evidence", {"eai:data":dashboard})
print(out.read_text())
