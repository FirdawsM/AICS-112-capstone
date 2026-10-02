# Lab 1: Control and risk register

| ID | Risk | Example failure | Required control | Test evidence |
|----|------|-----------------|------------------|---------------|
| R1 | Wrong entity | Disables a similarly named account | Resolve the immutable ID and require approval | Ambiguous-identity negative test |
| R2 | Repeated action | Playbook isolates the same endpoint twice | Idempotency key per incident and action | Re-run the same incident, second run returns already_completed |
| R3 | Prompt injection | Log text tells the AI to disable every account | Treat text as data, sanitize, fixed action allowlist | Injected evidence test, flag raised, actions stay in allowlist |
| R4 | Data leakage | Evidence sent to an unapproved model | Local Ollama only, data minimization | Input-field review of the AI request |
| R5 | Audit gap | No record of who approved containment | Append-only, hash-chained decision record | Approval audit test, tamper test returns BROKEN |
| R6 | False positive | Benign activity on a critical asset triggers isolation | Human approval gate, dry run, evaluated threshold | Precision and false-positive count from evaluate.py |
| R7 | False negative | Real attack scored low and never escalated | Threshold experiment, recall reported with the model card | Recall and fn count from evaluate.py |
| R8 | AI hallucination | Model invents an event or a user | Advisory only, analyst checks claims against event IDs | Ollama vs offline comparison file |
| R9 | AI provider failure | Ollama is down or times out | Offline fallback, error shown and recorded, not hidden | Fallback screenshot and provider_error text |
| R10 | Stale or weak intel | Low-confidence indicator causes a false IOC match | Confidence threshold of 70 on indicators | test_low_confidence_ioc_is_ignored |
| R11 | Weak approver identity | Anyone can type any name as approver | Minimum name check now, real authentication in production | Name under 3 characters is rejected |
