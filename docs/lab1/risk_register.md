# Risk register

| ID | Risk | Likelihood | Impact | Control |
|----|------|-----------|--------|---------|
| R1 | Prompt injection in event text steers the AI | Medium | High | Injection flagging, AI limited to a fixed list of allowed steps |
| R2 | False positive isolates a critical finance host | Medium | High | Human approval gate, dry run only |
| R3 | False negative: real attack scored low | Medium | High | Evaluation against ground truth, threshold experiment |
| R4 | AI hallucinates evidence | High | Medium | Advisory only, analyst checks claims against event IDs |
| R5 | Audit log tampered with | Low | High | Hash-chained log, verify script |
| R6 | Approver identity is weak (name only) | Medium | Medium | Minimum name check now, real authentication in production |
| R7 | Duplicate action run on replay | Medium | Medium | Idempotency ledger |
| R8 | Model or Ollama unavailable or times out | Medium | Low | Offline fallback, fallback recorded not hidden |
| R9 | Stale threat intel gives wrong IOC match | Medium | Medium | Confidence threshold of 70 on indicators |
| R10 | Sensitive data sent to an external AI API | Low | High | Local Ollama, no data leaves the machine |
