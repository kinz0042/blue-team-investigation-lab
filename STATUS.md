# Private review status

## Main investigation

The primary case uses the original OTRF Windows capture. Python and Splunk correlate Task Manager process 3405712, six LSASS access records before artifact creation and file record 3407010 by endpoint, process GUID and original UTC time. Splunk indexed 2,018 original Sysmon events for this check.

The separate repeated-failure case uses synthetic authentication/endpoint records. A complete captured repeated-failure-to-execution sequence has not been established. The main case's supported conclusion concerns an LSASS dump artifact. Credential extraction and later credential use were not examined.

## Verified

- 26 passing Python tests, including forwarded duplicates, conflicting source records, wrong provider channel, incorrect host/process and temporal order.
- Seven executed synthetic-case negative checks in Splunk.
- Four executed original-case negative checks in Splunk.
- Native original-case and synthetic-case dashboard PDF exports, rendered and visually checked.
- Actual command-output replay and a 40-second edited evidence walkthrough.
- Hosted GitHub validation on previous commits. The workflow regenerates public-capture reports and rejects changed results.
- Original capture archives, source commit, SHA256 and MIT license attribution.
- Investigation record, exact evidence IDs and response playbook.

## Unresolved access restriction

The chat browser rejected direct access to the running lab address with ERR_BLOCKED_BY_CLIENT. Loopback access returned a missing/invalid bearer-token response. Splunk's authenticated localhost API and native dashboard renderer were tested successfully.

Live Splunk Web browser validation and a live screen recording remain blocked in this environment. The delivered MP4 presents executed evidence and a native dashboard export. It is not a live screen recording.

Completing live browser work requires a Splunk instance reachable by the browser. No external hosting or account access has been configured for that purpose.

## Runtime and privacy

The repository remains private. Splunk runs in a temporary Linux workspace, with its official overlay-filesystem startup override. API validation accepts the localhost lab's self-signed certificate. Credentials and installer bytes remain outside the repository. Recreate the runtime when the workspace ends.

Production accuracy and operational deployment hardening remain unmeasured.
