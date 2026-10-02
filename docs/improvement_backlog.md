# Improvement backlog: AICS-112 AI-SOAR lab

Owner for all items: Firdaws Alnuur Mohammed. Findings come from Labs 4 to 6 evidence.

## Reliability
| ID | Item | Priority | Acceptance test | Target |
|---|---|---|---|---|
| R1 | Reject expired IOCs in `enrich_event` (check `valid_until`) | High | `test_expired_ioc_is_not_a_match` passes and no longer needs `expectedFailure` | v1.1 |
| R2 | Document Ollama warm-up and RAM needs in the README (timeout is now configurable via `AICS112_OLLAMA_TIMEOUT`; the request sets `think` to false) | High | On an 8 GB CPU-only laptop, "Ask AI" returns `ollama:` with no `provider_error`, or a clear fallback message | v1.1 |
| R3 | Use the idempotency ledger inside the real pipeline, not only in `idempotency_demo.py` | Medium | Running the pipeline twice on the same incident records `already_completed` for every action | v1.2 |
| R4 | Show a friendly message when the capstone dataset has not been extracted | Low | Selecting "Blind capstone" early shows a readable instruction, not a file-not-found error | v1.1 |

## Security
| ID | Item | Priority | Acceptance test | Target |
|---|---|---|---|---|
| S1 | Read the instructor approval token from an environment variable, not source code | High | `grep INSTRUCTOR-APPROVED` finds nothing in the student package; dry-run still works with the variable set | v1.1 |
| S2 | Enforce the 30-minute approval expiry from the playbook | Medium | An approval older than 30 minutes returns the step to `awaiting_approval` | v1.2 |
| S3 | Anchor the audit hash chain outside the app (for example, a daily head hash written to a separate read-only file) | Medium | Recomputing the whole chain after tampering is still detected against the anchored head hash | v1.3 |
| S4 | Bind the app and Ollama only to 127.0.0.1 and test it | Medium | A connection from another host to ports 8112 and 11434 is refused | v1.1 |

## AI governance
| ID | Item | Priority | Acceptance test | Target |
|---|---|---|---|---|
| G1 | Validate AI step lists: remove duplicates and require the baseline steps (preserve_evidence, notify_analyst) for critical incidents | High | A mocked model reply of `monitor` plus repeated steps is rejected or corrected, and the UI says so | v1.1 |
| G2 | Log model name, prompt hash and raw reply for every AI call in the audit trail | Medium | Each "Ask AI" call adds an audit record with model and prompt hash | v1.2 |

## Analyst experience
| ID | Item | Priority | Acceptance test | Target |
|---|---|---|---|---|
| A1 | Show which event IDs back each AI claim, and flag claims without one | Medium | Every claim in the AI box links to a TR-xxx event or shows "unsupported" | v1.2 |
| A2 | Show a countdown and requester name for pending approvals | Low | The panel lists time left for each awaiting_approval item | v1.3 |
