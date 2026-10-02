#!/usr/bin/env bash
# Dumps the facts needed for the incident report on SOAR-0006. Run from the repo root.
python3 - <<'PY'
import json
inc = [i for i in json.load(open("output/capstone/incidents.json")) if i["incident_id"] == "SOAR-0006"][0]
print({k: v for k, v in inc.items() if k not in ("events", "ai_assist")})
print("\nAI assist keys:", list(inc.get("ai_assist", {}).keys()))
print("\nEVENTS (id, timestamp, source, type, message):")
for e in inc.get("events", []):
    print(e.get("event_id"), e.get("timestamp"), e.get("source"), e.get("event_type"), e.get("message"), sep=" | ")
PY
echo; echo "== SOAR-0006 decisions =="
grep SOAR-0006 runtime/decisions.jsonl | cut -c1-220
