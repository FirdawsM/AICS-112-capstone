#!/usr/bin/env bash
# Lab 1, Task 1: inspect the evidence package. Run from the repo root.
set -u
OUT=docs/lab1/dataset_evidence.txt
mkdir -p docs/lab1
{
echo "== DATASET_MANIFEST.json =="; cat lab_data/training/DATASET_MANIFEST.json
echo; echo "== SHA-256 of events.jsonl =="; sha256sum lab_data/training/events.jsonl
echo; echo "== line count =="; wc -l lab_data/training/events.jsonl
echo; echo "== two most critical assets =="
python3 - <<'PY'
import csv
rows = list(csv.DictReader(open("lab_data/common/assets.csv")))
print("columns:", list(rows[0].keys()))
rows.sort(key=lambda r: -int(r.get("criticality") or 0))
for r in rows[:2]:
    print(r)
PY
echo; echo "== threat intel: indicator pattern, confidence, labels =="
python3 - <<'PY'
import json, glob
path = glob.glob("lab_data/**/threat_intel_stix.json", recursive=True)[0]
print("file:", path)
data = json.load(open(path))
objs = data.get("objects", data) if isinstance(data, dict) else data
for o in objs[:2]:
    print({k: o.get(k) for k in ("type", "pattern", "confidence", "labels")})
PY
} | tee "$OUT"
