# Lab 1: Workflow and trust boundary

```mermaid
flowchart LR
  A[Ingest events.jsonl] --> B[Normalize]
  B --> C[Enrich: assets, identities, threat intel]
  C --> D[Correlate: 45 min window, same user or asset]
  D --> E[Score: risk model + max severity]
  E --> F[Plan actions: dry run]
  F --> G{Human approval gate}
  G -->|approve or deny| H[Audit log: hash chained]
  F -->|low impact actions| H
  E -.advisory only.-> I[AI analyst: Ollama or offline fallback]
  I -.suggestions, no execution.-> G
```

Trust boundary: everything left of the approval gate is automated and read-only or dry run. The AI box has no path to execute an action. High-impact actions only pass the gate on a named human decision.
