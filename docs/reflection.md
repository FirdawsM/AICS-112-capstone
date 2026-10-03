# Reflection: SOAR-0006

## Decision 1: isolate_endpoint (approved, simulated)
I approved isolation of OPS-WS-009 because the endpoint showed encoded PowerShell launched from a spreadsheet process (CP-006), a 60-second beacon to 203.0.113.77 (CP-007) and a 96 MB upload to the same address (CP-009). Isolation stops the beacon and the exfiltration, can be reversed by releasing the host, and the evidence came from several independent sources.

## Decision 2: disable_identity (denied)
I denied this one to test the deny path and to confirm that a denied action is written to the audit log and is not executed. That was a test choice, not an operational judgement. In a real incident I would approve it, because the sign-in from Ghana (CP-004) is a confirmed account takeover and the account can be re-enabled if it turns out to be a false positive. Leaving it active keeps attacker access open.

## Decision 3: revoke_oauth_grant (denied)
I denied this one for the same reason. In a real incident I would approve it, because the consent to the unverified app MailSync Pro (CP-005) gives persistence that survives a password reset, so a reset alone would not remove the attacker.

## Limit I found
The pipeline correlates events only by the same user or asset within a 45-minute window. Incidents on different users that share an attacker IP are not linked, so related activity can appear as separate incidents.

## Backlog items
1. Link incidents that share an attacker IP or other indicator.
2. Make the 30-minute approval expiry real and log the model name and prompt hash for AI calls.