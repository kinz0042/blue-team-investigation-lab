# Tier 1 investigation record

12 November 2026 · UTC · Simulated case

## Escalate the jump-host alert

At 09:05:02, OPS-JUMP01 recorded a successful remote-interactive logon for LAB\a.okoro from 198.51.100.24. Records 2001–2006 show six failures from the same source beginning at 09:01:05. Record 2007 shows the success 43 seconds after the last failure. Record 2008 is a second success. It brings no new failures and creates no second alert.

At 09:13, service-desk callback HD-417 documented the user's denial. The session reached an administration jump host, so the asset's role and the independently recorded denial raise the priority. The alert supports suspected unauthorized access. Actions performed during the session and the identity of the operator remain unknown.

Disposition: escalate to Tier 2 as high priority. Send the seven triggering records, the additional success and HD-417. Request endpoint session and process records from 09:01 onward and any VPN or gateway mapping for the source. Ask the incident lead to assess session termination and credential reset under the organization's response procedure. Containment remains pending.

## Close the training-workstation alert

OPS-DESK03 recorded five failures for LAB\d.bello from 192.0.2.60 between 09:11:05 and 09:13:45 (records 1003–1007). Record 1008 shows a successful remote-interactive logon at 09:14:00.

Booking TR-118 matches the user, destination, source and time window. The trainer separately confirmed the exercise and five rejected entries. Close this alert as expected training activity. The detector matched its rule correctly. A blanket account or workstation exclusion would hide later activity outside this booking.

## Review of other records

Record 2003 appears twice in the CSV and counts once. The five failures for j.kalu have no matching success from the same address. The svc.inventory events use logon type 3. Record 2021 lacks a source address and cannot be correlated by this rule. These exclusions explain the detector's output and do not establish whether the excluded activity was authorized.
