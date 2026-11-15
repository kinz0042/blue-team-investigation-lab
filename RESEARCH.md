# Research and selection
Research date 14 November 2026.

Cybrella's junior SOC role asks for SIEM alert analysis, endpoint investigations, correlation, escalation, reports and playbooks. This informed the deliverables.
https://www.cybrella.io/jobs/junior-soc-analyst

MITRE DET0269 AN0750 describes remote access followed by uncommon execution and connections, using Security and Sysmon telemetry. This project implements a narrow example of that approach.
https://attack.mitre.org/detectionstrategies/DET0269/

Microsoft documents process GUIDs for correlation despite process ID reuse. This project preserves process identity in network joins.
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

Splunk attack_data supports reproducible detection development and replay. The project uses that testing approach with its own synthetic cases. No Splunk dataset validation is claimed.
https://github.com/splunk/attack_data

Sigma supplies a generic detection and correlation specification. This project's executable rules are Python and make no Sigma compatibility claim.
https://sigmahq.io/sigma-specification/

| Project option | Evidence it can demonstrate | Delivery tradeoff |
| --- | --- | --- |
| SIEM deployment | Installation and ingestion | Needs investigation and testing to demonstrate analyst judgment |
| Phishing triage | Email parsing and prioritization | Narrower endpoint analysis |
| Remote access investigation | Normalization, correlation, triage, tests and reports | Requires explicit synthetic-data labeling |
| Enterprise cyber range | Broad infrastructure and response | Larger infrastructure overhead |

Selected remote access investigation for one reproducible case. Sources support the technical direction and sampled role requirements. They cannot guarantee employer interest. The project now includes a separately labeled original OTRF laboratory capture, executed Splunk searches, negative checks and authenticated browser verification. A complete captured repeated-failure-to-execution sequence and production accuracy remain unverified.
