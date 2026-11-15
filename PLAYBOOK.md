# Investigation response playbooks

## LSASS access and dump artifact

Use this playbook when one process accesses LSASS and creates a possible dump artifact. The bundled example concerns an original captured laboratory sequence. No response action was executed.

| Stage | Analyst action | Evidence or decision to record |
| --- | --- | --- |
| Validate | Check endpoint identity, Sysmon channel, original UTC timestamps and shared process GUID. Distinguish other Task Manager instances. | Process 3405712, access records 3406235–3406239 and 3407009, artifact 3407010. |
| Preserve | Preserve source events. Ask the authorized endpoint responder to acquire the possible dump and record hashes, acquisition time and handling. | Artifact existence, contents and custody are pending in this case. |
| Establish context | Collect process ancestry, full command line, account privileges, interactive session details and approved diagnostic activity. Verify authorization independently. | Authorization and parent-process context are unresolved. |
| Escalate | Send the endpoint, account, UTC timeline, linked records and precise uncertainty to the incident lead. | Suspected credential dumping warrants investigation. Extraction and credential use are unproven. |
| Assess containment | Ask the incident lead to assess isolation and credential controls against business impact and exposure. Preserve evidence before disruptive steps when feasible. | Record approval, action owner, time and verified outcome. Never mark a proposed action complete. |
| Scope | Hunt the same account, process ancestry and artifact pattern across endpoints. Review subsequent authentication and remote access. | Record additional affected assets or the limits of available telemetry. |
| Close | Document the validated explanation, response results and remaining evidence gaps. Replay the rule after any tuning. | Approved diagnostics need specific authorization evidence. An absent artifact alone does not justify benign closure. |

### Example escalation

WORKSTATION5.theshire.local recorded Taskmgr.exe under THESHIRE\pgustavo at 08:38:11.620 UTC on 22 September 2020. The same process GUID accessed LSASS in six preceding events and created an LSASS-named dump artifact at 08:38:27.371 UTC. Process record 3405712 and file record 3407010 support escalation as suspected credential dumping. Authorization, artifact contents and subsequent credential use remain unresolved. Request evidence acquisition and an incident-lead containment assessment. No containment has been performed.

## Remote access after repeated failures

1. Inspect missing sources, absent session mappings, record conflicts and time offsets.
2. Verify the successful Security event and preceding failures against their source records.
3. Validate session mapping and process GUID. Collect the parent process, command line, hash and signature.
4. Check expected access through asset inventory, VPN records and an independently verified user callback.
5. Investigate destination ownership, proxy, DNS and endpoint evidence. A network connection alone cannot establish data theft.
6. Escalate suspected unauthorized privileged access with UTC timeline, exact evidence IDs and outstanding questions. Request the incident lead to assess session termination, credential controls and isolation under local procedure.
7. Record containment only after execution is verified. Preserve evidence and hunt related sessions.
8. Close expected activity with specific supporting evidence. Scope exceptions to approved accounts, sources, hosts and times. Replay benign and suspicious cases after tuning.

For the fictional sample, prioritize a.okoro on OPS-JUMP01. User denial and the jump-host role strengthen concern. Training booking TR-118 supports closing d.bello's alert. Containment remains unexecuted.
