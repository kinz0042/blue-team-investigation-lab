# Completion status

## Verified in Linux
- Replayed synthetic authentication, process and network evidence.
- Passed 19 tests, including rejection of network events before process creation.
- Imported the original OTRF Windows capture with pinned source commit, SHA256 and MIT license.
- Inventoried all 110 public-capture events. This capture lacks Security 4624/4625 and Sysmon 1/3. It cannot validate the remote-access chain.
- Generated reproducible JSON and HTML case reports.

## Delivered but not runtime-validated
- GitHub Actions workflow.
- Draft encoded-PowerShell SPL.
- Windows event export script.

## Pending
- A complete captured dataset containing the authentication and linked process/network sequence.
- Splunk installation, ingestion, full correlation searches and dashboard validation.
- Dashboard screenshots and recorded end-to-end demonstration.

This environment has no Docker, QEMU or /dev/kvm available. Splunk's download page requires an account. The Windows capture is external lab evidence, while the regression scenario is synthetic. These limitations prevent declaring the full planned project finished.
