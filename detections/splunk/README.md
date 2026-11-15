# Executed Splunk validation

Splunk Enterprise 10.6.1.1 ran locally on Linux. reports/splunk-validation.json records the actual executed results.

32 synthetic authentication rows and seven endpoint rows were ingested into blue_team. Authentication SPL found success 2007 after six failures and success 1008 after five. The endpoint query linked p41 to n42 in session 0x71a and excluded distractor p99. The runner assigns priorities by matching successful Security record IDs from these two component searches.

validated-authentication.spl and validated-session-chain.spl contain the executed searches. Replace <VALIDATION_RUN> with the recorded run_id. Keep run filtering to prevent repeated replay batches from mixing.

The dashboard.xml was registered as blue_team_evidence in Splunk's Search app. Its searches target the recorded run. Both dashboard panels were verified in Splunk Web. See ../../demo/live-dashboard.mp4.

## Reproduce
Start your local Splunk instance. Place the admin password in a private local file, then run:

SPLUNK_PASSWORD_FILE=/path/to/private/password.txt python3 detections/splunk/validate.py

The validator defaults to HTTPS localhost:8089, admin credentials and a locally self-signed certificate. Certificate verification is disabled specifically in this localhost lab client. Keep it local. It creates the blue_team index, ingests a uniquely tagged replay and asserts expected results. It also creates or updates the dashboard.

The original encoded-powershell.spl remains an unexecuted draft. The validated chain query checks the two flags in command text and needs executable matching and additional negative cases before production use. Validation covers the bundled replay, not arbitrary production events.

## Runtime decisions
The official installer SHA256 was 8525ed14ddfafa1a2b6d1f9167a36fb9a4af5486b93612bf55cc4d818c5e9d71.
Startup required OPTIMISTIC_ABOUT_FILE_LOCKING=1 on this workspace's overlay filesystem. This is a temporary lab setting. Splunk's startup license was accepted. The runtime and credentials are excluded from this repository.

## Negative cases executed
reports/splunk-negative-tests.json records seven executed cases with zero chains expected and observed: wrong executable, wrong process GUID, wrong host, wrong session, network before process, process after the fifteen-minute window, and missing logon mapping. These cases run against mutations of the indexed fixture fields. The chain now verifies the executable name and keeps network evidence grouped by host/session/process GUID. Priority assignment also checks destination hostname.

## Original public-capture case
Apply public-props.conf to the lab instance and restart it before running validate_public.py with SPLUNK_PASSWORD_FILE. The source capture is over six years old. The configuration assigns current ingestion time while retaining the original Sysmon UtcTime for forensic ordering. The query explicitly parses that original time.

The public validator ingests all 2,018 Sysmon process creation, process access and file creation events from the original capture. It checks the earliest LSASS-named artifact per process. Access evidence must fall between process creation and that artifact. The query preserves endpoint Hostname instead of relying on the collector host.

The case is independently corroborated by investigate_public_rdp.py. It concerns an LSASS dump artifact. It does not prove credential extraction or subsequent credential use.

## Original case negative validation and dashboard

validate_public.py now executes four negative cases against the actual original-capture query. All must return zero artifacts: wrong artifact process GUID, wrong endpoint hostname, artifact before access, and missing process creation. Results are in reports/splunk-public-negative-tests.json.

The validator registers public_lsass_evidence and uses Splunk's native PDF renderer to export reports/public-dashboard.pdf. The rendered preview is reports/public-dashboard.png. Both exports were visually checked. Authenticated browser access and the displayed original-evidence row were verified on 15 November 2026.

## Desktop runtime used for live verification

The temporary desktop runtime used Web port 18000 and management port 18089. Set httpport and mgmtHostPort in Splunk web.conf and SPLUNKD_PORT in splunk-launch.conf to matching local ports. Start Splunk in the desktop terminal so the browser can reach the same runtime. Set NO_PROXY=localhost,127.0.0.1 when starting it in an environment with proxy variables.

Run each validator with SPLUNK_BASE_URL=https://127.0.0.1:18089 and SPLUNK_PASSWORD_FILE pointing to a private local password file. The clients accept only localhost HTTPS origins and bypass environment proxies for these requests. Their self-signed certificate exception is limited to the local lab. Credentials remain outside this repository.

SimpleXML dashboard queries begin with index=. Splunk Web adds its search command prefix. The API searches retain their explicit search prefix. This distinction is covered by tests/test_dashboards.py.
