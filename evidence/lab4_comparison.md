# Lab 4: Ollama (qwen3:4b) vs offline baseline, SOAR-0001

| Item | Ollama qwen3:4b | Offline baseline |
|---|---|---|
| Provider | ollama:qwen3:4b | offline-explainable-baseline |
| Confidence | high | high |
| Evidence | 8 items, each cited to TR-001 to TR-008, all correct | 6 factor labels, no event IDs |
| Next steps | monitor, then request_identity_disable_approval x3 | 6 distinct allowed steps |
| Uncertainties | 3 specific to the incident | 3 generic |
| Response time | 2m27s on 8 CPU cores, no GPU | instant |

## Findings
1. Evidence: every Ollama claim matches an event ID. No invented facts found.
2. Wording: the summary says the asset was "compromised". The events show consistent signals, not proof, so this overclaims.
3. Steps: all tokens are in the allowlist, so the validator worked. But the list repeats one step three times, and it recommends monitor for a critical incident. It misses preserve_evidence, notify_analyst, collect_triage and request_isolation_approval.
4. Conclusion: the model adds useful event-level detail but is not reliable for choosing actions. The allowlist, the advisory-only rule and the human approval gate are what keep it safe.

## Run notes
- First attempts hit the timeout and fell back safely (see lab4_ai_analysis_ollama_FALLBACK.json and lab4_fallback_timeout screenshots).
- Fix that worked: /no_think in the prompt, freeing RAM (the machine was swapping), and AICS112_OLLAMA_TIMEOUT.
