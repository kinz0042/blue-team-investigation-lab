# Release status

## Verified deliverables

- Offline Python investigation for the synthetic remote-access sequence.
- Original OTRF Windows case linking Task Manager creation, six LSASS access records and a dump-file artifact by endpoint, process GUID and UTC event time.
- 23 passing Python tests.
- Executed Splunk authentication and endpoint correlation searches.
- Seven executed negative Splunk cases with no false chain.
- Splunk corroboration of the original public case using 2,018 indexed Sysmon events.
- Registered dashboard and native Splunk PDF export. Its two synthetic-case panels were rendered and visually inspected.
- Actual command-output demonstration, available as offline HTML with its recorded output and exit codes.
- Source provenance, MIT attribution, capture hashes, investigation decisions and response playbook.

## Practical limits

The repeated-failure case uses synthetic records. The separate original Windows case validates process/access/artifact linkage and has no failed logons. A single original capture containing the whole repeated-failure-to-execution sequence remains future work.

The live Splunk Web interface could not be reached through this chat's browser. The native exported PDF/PNG were verified instead. There is no live dashboard screen recording. The supplied demonstration replays captured command output.

Splunk runs in a temporary Linux workspace with an overlay filesystem startup override. Its local API validator accepts a self-signed certificate on localhost only. Runtime credentials and installer files are outside the repository. Availability of the running instance ends with the workspace session.

Python tests and SPL scenario checks passed locally. GitHub Actions run 43636367261 passed on commit 63317c3. The workflow now also regenerates the original public-capture reports and checks for changed results. Production accuracy and deployment hardening are outside this lab release.
