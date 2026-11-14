# Public capture investigation

Source is OTRF's original RDP/Task Manager lab capture, pinned to commit d9d40ef123d2c87d5d3df28c96bcab4f0faccc87. This investigation concerns captured laboratory behavior. The source filename supplies scenario context. Findings below rely on event records.

## Observed sequence

On WORKSTATION5.theshire.local, Sysmon record 3405712 created Taskmgr.exe under THESHIRE\pgustavo at 08:38:11.620 UTC on 22 September 2020. Its process GUID ends df02-000000000900.

Six LSASS access records from that GUID occur before file record 3407010. At 08:38:27.371 UTC, that same process created C:\Users\pgustavo\AppData\Local\Temp\lsass.DMP.

A second Task Manager process, record 3405383, has a different GUID ending dd02-000000000900. The investigation excludes it from the access/file sequence.

Use Sysmon UtcTime for ordering. The capture also carries collector timestamps and EventTime fields that differ. The original capture remains intact.

## Assessment and response

The shared process identity, LSASS target and named dump artifact warrant escalation as suspected credential dumping. The file's contents, resulting credentials, subsequent credential use and authorization were not examined. File creation alone cannot establish successful extraction.

Preserve the source events and acquire the artifact through the organization's approved evidence procedure. Request endpoint process context, user authorization and session evidence. The incident lead should assess containment and credential exposure. No containment action was performed in this investigation.

## Reproduce

Run python3 investigate_public_rdp.py, then inspect reports/public-rdp-investigation.json. Run python3 -m unittest discover -s tests -v for linkage and negative cases.

This capture includes 18 successful logons but no failed logons. It validates the process/access/artifact case, while the earlier repeated-failure scenario remains a separate synthetic regression.
