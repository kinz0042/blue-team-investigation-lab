# Release status

## Main investigation

The primary case uses the original OTRF Windows capture. Python and Splunk correlate Task Manager process 3405712, six LSASS access records before artifact creation and file record 3407010 by endpoint, process GUID and original UTC time. Splunk indexed 2,018 original Sysmon events for this check.

The separate repeated-failure case uses synthetic authentication/endpoint records. A complete captured repeated-failure-to-execution sequence has not been established. The main case's supported conclusion concerns an LSASS dump artifact. Credential extraction and later credential use were not examined.

## Verified

- 27 passing Python tests, including forwarded duplicates, conflicting source records, wrong provider channel, incorrect host/process and temporal order.
- Seven executed synthetic-case negative checks in Splunk.
- Four executed original-case negative checks in Splunk.
- Native original-case and synthetic-case dashboard PDF exports, rendered and visually checked.
- Actual command-output replay and a 40-second edited evidence walkthrough.
- Hosted GitHub validation passed for the live-dashboard fix at commit 5e3ed1d43f83e54635298fa3629344d3f80f3309. The workflow regenerates public-capture reports and rejects changed results.
- Original capture archives, source commit, SHA256 and MIT license attribution.
- Investigation record, exact evidence IDs and response playbook.

## Live access verified

On 15 November 2026, Splunk Web was reached through the cloud browser at localhost port 18000 after starting Splunk from the desktop terminal. Both authenticated dashboards returned their expected evidence rows. The original-evidence view showed process 3405712 and artifact 3407010. The synthetic view showed both authentication findings and the p41/n42 session chain.

A duplicated search prefix caused empty dashboard panels even when API searches succeeded. Both XML generators now omit that prefix. A regression test checks the generated XML. Both validators were rerun successfully after this fix.

The 16.8-second demo/live-dashboard.mp4 records actual browser navigation through sampled screenshots. demo/live-recording.json describes its capture method. reports/public-dashboard-live.jpg shows the live original-evidence result. The earlier edited walkthrough remains separately identified.

## Runtime and privacy

The repository was made public on 15 November 2026. Splunk runs in a temporary Linux workspace, with its official overlay-filesystem startup override. API validation accepts the localhost lab's self-signed certificate. Credentials and installer bytes remain outside the repository. Recreate the runtime when the workspace ends.

Production accuracy and operational deployment hardening remain unmeasured.
