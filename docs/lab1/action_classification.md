# Action classification

| # | Action | Class | Approval | Reversible | Source |
|---|--------|-------|----------|------------|--------|
| 1 | create_case | Read-only / low impact | No | Yes | Lab |
| 2 | notify_analyst | Read-only / low impact | No | Yes | Lab |
| 3 | collect_endpoint_triage | Read-only (collects data) | No | Yes | Lab |
| 4 | preserve_evidence | Read-only | No | Yes | AI step |
| 5 | verify_identity | Read-only | No | Yes | AI step |
| 6 | isolate_endpoint | High impact | Yes | Partly | Lab |
| 7 | disable_identity | High impact | Yes | Partly | Lab |
| 8 | revoke_oauth_grant | High impact | Yes | Partly | Capstone |
| 9 | block_domain (extra) | High impact | Yes | Yes | Added by me |
| 10 | reset_password (extra) | High impact | Yes | No | Added by me |
