# Completion status

## Verified in Linux
- Replayed synthetic authentication, process and network evidence.
- Passed 19 tests, including rejection of network events before process creation.
- Imported the original OTRF Windows capture with pinned source commit, SHA256 and MIT license.
- Inventoried all 110 public-capture events. This capture lacks Security 4624/4625 and Sysmon 1/3. It cannot validate the remote-access chain.
- Generated reproducible JSON and HTML case reports.

## Delivered but not runtime-validated
- GitHub Actions workflow.
- Original draft encoded-PowerShell SPL. Executed component searches and their recorded results are now delivered.
- Windows event export script.

## Pending
- A complete captured dataset containing the authentication and linked process/network sequence.
- Additional SPL negative cases and dashboard visual validation.
- Dashboard screenshots and recorded end-to-end demonstration. The dashboard is registered, but its rendering remains unverified.

This environment has no Docker, QEMU or /dev/kvm available. Splunk's download page requires an account. The Windows capture is external lab evidence, while the regression scenario is synthetic. These limitations prevent declaring the full planned project finished.

## Splunk milestone
Splunk 10.6.1.1 installed and authenticated search executed. The uniquely tagged replay ingested 39 rows and produced authentication findings 2007/1008. Process p41 linked to n42 in the correct session. A dashboard definition was registered. See reports/splunk-validation.json and detections/splunk/README.md for limits.
