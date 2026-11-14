import os
import urllib.error
import base64,json,ssl,time,urllib.request,urllib.parse,zipfile
from pathlib import Path
project=Path(__file__).resolve().parents[2]
token=base64.b64encode(("admin:"+Path(os.environ["SPLUNK_PASSWORD_FILE"]).read_text().strip()).encode()).decode()
def request(path,body):
    req=urllib.request.Request("https://127.0.0.1:8089"+path,data=body)
    req.add_header("Authorization","Basic "+token)
    data=urllib.request.urlopen(req,context=ssl._create_unverified_context(),timeout=120).read()
    return data if data.startswith(b"%PDF") else data.decode()
def search(query):
    lines=request("/services/search/jobs/export",urllib.parse.urlencode({"search":query,"output_mode":"json"}).encode())
    rows=[json.loads(l) for l in lines.splitlines() if l.strip()]
    errors=[m for r in rows for m in r.get("messages",[]) if m["type"]=="ERROR"]
    if errors:raise RuntimeError(errors)
    return [r["result"] for r in rows if "result" in r]
with zipfile.ZipFile(project/"data/public/rdp-capture.zip") as z:
    events=[json.loads(l) for l in z.read(z.namelist()[0]).decode().splitlines() if l.strip()]
selected=[e for e in events if str(e.get("Channel","")).casefold()=="microsoft-windows-sysmon/operational" and e.get("EventID") in {1,10,11}]
run_id=str(time.time_ns())
for e in selected:e["validation_run"]=run_id
request("/services/receivers/simple?index=blue_team&sourcetype=bt:public_sysmon",("\n".join(json.dumps(e) for e in selected)+"\n").encode())
base='search index=blue_team sourcetype=bt:public_sysmon validation_run="'+run_id+'" earliest=0 | fields _raw | spath'
for _ in range(30):
    rows=search(base+" | stats count")
    if rows and int(rows[0]["count"])==len(selected):break
    time.sleep(1)
else:raise RuntimeError("Incomplete ingestion")
query=base+"""
| eval process_guid=lower(coalesce(SourceProcessGUID,ProcessGuid)), endpoint=lower(Hostname), event_time=strptime(UtcTime,"%Y-%m-%d %H:%M:%S.%3N")
| eventstats min(eval(if(EventID=1,event_time,null()))) as process_start values(eval(if(EventID=1,RecordNumber,null()))) as process_records by endpoint process_guid
| eventstats min(eval(if(EventID=11 AND like(lower(TargetFilename),"%lsass.dmp"),event_time,null()))) as artifact_time by endpoint process_guid
| eval qualifying_access=if(EventID=10 AND like(lower(TargetImage),"%lsass.exe") AND event_time>=process_start AND event_time<=artifact_time,1,0)
| eventstats min(eval(if(qualifying_access=1,event_time,null()))) as first_access values(eval(if(qualifying_access=1,RecordNumber,null()))) as access_records by endpoint process_guid
| where EventID=11 AND like(lower(TargetFilename),"%lsass.dmp") AND event_time>=first_access AND isnotnull(process_start)
| table Hostname process_guid process_records access_records RecordNumber TargetFilename UtcTime"""
rows=search(query)
negative_cases = [
    ("wrong_artifact_process", 'eval ProcessGuid=if(RecordNumber=3407010,"{OTHER}",ProcessGuid)'),
    ("wrong_artifact_host", 'eval Hostname=if(RecordNumber=3407010,"OTHER-HOST",Hostname)'),
    ("artifact_before_access", 'eval UtcTime=if(RecordNumber=3407010,"2020-09-22 08:38:11.700",UtcTime)'),
    ("missing_process_creation", 'where EventID!=1'),
]
negative_results = []
for name, mutation in negative_cases:
    actual = search(query.replace(base, base+" | "+mutation, 1))
    if actual:
        raise RuntimeError("False positive in "+name+": "+str(actual))
    negative_results.append({"case":name,"expected":0,"actual":len(actual),"passed":True})
(project/"reports/splunk-public-negative-tests.json").write_text(json.dumps(negative_results,indent=2)+"\n")
assert len(rows[0].get("access_records",[]))==6,rows
assert len(rows)==1 and int(rows[0]["RecordNumber"])==3407010,rows
(project/"detections/splunk/public-lsass-artifact.spl").write_text(query.replace(run_id,"<VALIDATION_RUN>")+"\n")
(project/"reports/splunk-public-validation.json").write_text(json.dumps({"run_id":run_id,"indexed_sysmon_rows":len(selected),"results":rows,"source":"data/public/rdp-capture.zip"},indent=2)+"\n")
print(json.dumps({"indexed":len(selected),"findings":rows},indent=2))


# Register and natively render the public-evidence dashboard.
import html
dashboard = '<dashboard version="1.1"><label>Original Windows LSASS Artifact Investigation</label><description>Original OTRF laboratory capture. Correlated evidence supports investigation of a dump artifact. Credential extraction was not examined.</description><row><panel><table><title>Process, preceding LSASS access and artifact</title><search><query>' + html.escape(query+' | table Hostname process_records RecordNumber TargetFilename') + '</query><earliest>0</earliest><latest>now</latest></search></table></panel></row></dashboard>'
try:
    request("/servicesNS/admin/search/data/ui/views",urllib.parse.urlencode({"name":"public_lsass_evidence","eai:data":dashboard}).encode())
except urllib.error.HTTPError as error:
    if error.code!=409:
        raise
    request("/servicesNS/admin/search/data/ui/views/public_lsass_evidence",urllib.parse.urlencode({"eai:data":dashboard}).encode())
(project/"detections/splunk/public-dashboard.xml").write_text(dashboard+"\n")
data=request("/services/pdfgen/render",urllib.parse.urlencode({"input-dashboard":"public_lsass_evidence","namespace":"search","owner":"admin","paper-size":"a4-landscape"}).encode())
if not isinstance(data,bytes) or not data.startswith(b"%PDF"):
    raise RuntimeError("Dashboard export did not return PDF")
(project/"reports/public-dashboard.pdf").write_bytes(data)
print("Public dashboard exported and four negative cases passed.")
