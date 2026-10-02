# Lab 1: Response action classification

Trigger for every action: an incident reaches the plan step with the risk band shown. All adapters run with dry_run = true.

| # | Action | Condition to plan it | Impact | Reversible | Approval | Rollback | Audit record | Status |
|---|--------|----------------------|--------|-----------|----------|----------|--------------|--------|
| 1 | create_case | Any incident | Low | Yes | No | Close the case | Yes | Implemented |
| 2 | notify_analyst | Medium risk and above | Low | Yes | No | None needed | Yes | Implemented |
| 3 | collect_endpoint_triage | High or critical risk | Low (read-only collection) | Yes | No | Delete the collected copy | Yes | Implemented |
| 4 | preserve_evidence | Any confirmed incident | Low (read-only) | Yes | No | None needed | Yes | AI advised step |
| 5 | verify_identity | Identity anomaly in the group | Low (read-only) | Yes | No | None needed | Yes | AI advised step |
| 6 | isolate_endpoint | Critical asset with malware or exfil signal | High | Partly | Yes, named analyst | Release the host from isolation | Yes | Implemented |
| 7 | disable_identity | Identity anomaly plus malware signal | High | Partly | Yes, named analyst | Re-enable the account and review sessions | Yes | Implemented |
| 8 | revoke_oauth_grant | Suspicious OAuth grant on the user | High | Partly | Yes, named analyst | User re-grants after review | Yes | Capstone |
| 9 | block_domain | Confirmed malicious domain, IOC confidence 70 or more | High | Yes | Yes | Remove the block entry | Yes | Design only |
| 10 | reset_password | Credential theft suspected | High | No | Yes | Cannot undo, issue a new reset | Yes | Design only |
| 11 | quarantine_email | Phishing delivered to several users | Medium | Yes | Yes | Restore from quarantine | Yes | Design only |

Rows marked Design only are part of the design for this lab and are not implemented in the code. The Capstone row appears only in the blind capstone plan.
