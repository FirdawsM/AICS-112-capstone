# AICS-112 AI-Driven SOAR Capstone: SavannaPay

Student: Firdaws Alnuur | ICDFA registration: 2026-AICDF-16701

A mini SOAR pipeline for a synthetic microfinance environment. It ingests events from email, identity, endpoint, proxy and network sources, normalizes and enriches them, correlates them into incidents, scores risk, and plans response actions. Every action is dry run. High-impact containment waits for a named human decision, and every decision lands in a hash-chained audit log. An AI analyst (local Ollama model or an offline fallback) advises only.

## Requirements

Python 3.11 or later. Ollama is optional and only needed for the Week 2 AI exercise. No paid API key is used.

## Run it

```bash
# 1. Tests
python3 -m unittest discover -s tests -v

# 2. Training dataset, then metrics
python3 run_pipeline.py --dataset lab_data/training --output output/training
python3 evaluate.py --incidents output/training/incidents.json --truth lab_data/training/ground_truth.csv

# 3. Blind capstone dataset
python3 run_pipeline.py --dataset lab_data/capstone --output output/capstone

# 4. Audit chain check
python3 verify_audit.py evidence/capstone/audit_log_with_approvals.jsonl

# 5. Console at http://127.0.0.1:8112
python3 app.py
```

## Ollama setup

```bash
ollama pull qwen3:4b
AICS112_AI_PROVIDER=ollama AICS112_OLLAMA_MODEL=qwen3:4b AICS112_OLLAMA_TIMEOUT=300 python3 app.py
```

The badge should read `ollama • qwen3:4b • dry-run-only`. The default 90 second limit timed out on my CPU-only machine, so the timeout is set with `AICS112_OLLAMA_TIMEOUT`. If Ollama fails or times out, the console shows the error and uses the offline model. Keep Ollama bound to 127.0.0.1.

## Evidence map

| Folder | Contents |
|--------|----------|
| docs/lab1/ | Architecture diagram, risk register, action classification, 150-word justification, dataset evidence |
| docs/ | Incident report, individual reflection |
| evidence/ | Test output, metrics, AI comparison, injection test, fallback record |
| evidence/lab5/ | Playbook, approval and idempotency evidence |
| evidence/capstone/ | Capstone incidents.json, audit logs, decisions.jsonl, chain check |
| evidence/screenshots/ | Console screenshots for Labs 4, 5 and 7 |

## Safety boundary

- All adapters run with `dry_run = true`. No real system is changed.
- isolate_endpoint, disable_identity and revoke_oauth_grant need a named approver of 3 or more characters.
- Event text is treated as data. Prompt injection is flagged, and AI steps stay inside a fixed allowlist.
- The audit log is hash-chained. Changing one old record makes `verify_audit.py` report a break.

## AI-assistance declaration

I used Claude (Anthropic) as a study and engineering assistant. It guided the lab walkthrough, drafted test code and documentation, and helped me debug command and path errors. I ran every command myself on my own machine, checked outputs against the evidence files, and can explain the submitted code and each approval decision. Where AI output was wrong or incomplete, I corrected it. I accept responsibility for every automation and incident-response decision in this submission. The signed declaration page (Template F) is in docs/.

<!-- EDIT: change this paragraph so it matches exactly what you used AI for. -->
