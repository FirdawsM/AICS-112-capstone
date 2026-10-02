from __future__ import annotations

import csv
import hashlib
import json
import math
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


FEATURE_WEIGHTS = {
    "intercept": -2.7,
    "ioc_match": 2.35,
    "multi_source": 1.25,
    "critical_asset": 0.85,
    "privileged_identity": 1.05,
    "malware_signal": 1.75,
    "identity_anomaly": 1.35,
    "exfil_signal": 1.85,
}


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON at {path}:{line_number}: {exc}") from exc
    return rows


def load_csv_index(path: Path, key: str) -> dict[str, dict]:
    with path.open(encoding="utf-8", newline="") as fh:
        return {row[key]: row for row in csv.DictReader(fh)}


def parse_stix_indicators(path: Path) -> list[dict]:
    bundle = json.loads(path.read_text(encoding="utf-8"))
    indicators = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern", "")
        match = re.search(r"=\s*'([^']+)'", pattern)
        if match:
            indicators.append({"value": match.group(1).lower(), "confidence": int(obj.get("confidence", 0)), "labels": obj.get("labels", []), "valid_from": obj.get("valid_from"), "valid_until": obj.get("valid_until")})
    return indicators


def normalize_event(raw: dict) -> dict:
    required = {"event_id", "timestamp", "source", "event_type", "severity"}
    missing = sorted(required - set(raw))
    if missing:
        raise ValueError(f"Event is missing required fields: {', '.join(missing)}")
    stamp = str(raw["timestamp"])
    if stamp.endswith("Z"):
        stamp = stamp[:-1] + "+00:00"
    parsed = datetime.fromisoformat(stamp)
    if parsed.tzinfo is None:
        raise ValueError(f"Timestamp must include a timezone: {raw['timestamp']}")
    result = dict(raw)
    result["timestamp"] = parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    result["severity"] = max(0, min(100, int(raw["severity"])))
    result["source"] = str(raw["source"]).lower()
    result["event_type"] = str(raw["event_type"]).lower()
    return result


# Lab 7 improvement 1: indicators are only trusted inside their STIX validity window.
def _parse_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def indicator_is_valid(indicator: dict, at: datetime) -> bool:
    start, end = _parse_utc(indicator.get("valid_from")), _parse_utc(indicator.get("valid_until"))
    return not ((start and at < start) or (end and at > end))


def enrich_event(event: dict, assets: dict[str, dict], identities: dict[str, dict], indicators: list[dict]) -> dict:
    result = dict(event)
    asset = assets.get(event.get("asset", ""), {})
    identity = identities.get(event.get("user", ""), {})
    result["asset_criticality"] = int(asset.get("criticality", 0) or 0)
    result["business_unit"] = asset.get("business_unit", "")
    result["privileged_identity"] = int(identity.get("privileged", 0) or 0)
    result["identity_risk_tier"] = identity.get("risk_tier", "")
    observed = {str(event.get(k, "")).lower() for k in ("domain", "src_ip", "dest_ip", "file_hash")} - {""}
    at = _parse_utc(event.get("timestamp")) or datetime.now(timezone.utc)
    matches = [i for i in indicators if i["value"] in observed and i["confidence"] >= 70 and indicator_is_valid(i, at)]
    result["ioc_matches"] = matches
    result["ioc_match"] = bool(matches)
    return result


def correlate(events: list[dict], window_minutes: int = 45) -> list[list[dict]]:
    ordered = sorted(events, key=lambda row: row["timestamp"])
    groups: list[list[dict]] = []
    for event in ordered:
        stamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        placed = False
        for group in groups:
            last_stamp = datetime.fromisoformat(group[-1]["timestamp"].replace("Z", "+00:00"))
            same_entity = bool(event.get("user") and event.get("user") == group[-1].get("user")) or bool(event.get("asset") and event.get("asset") == group[-1].get("asset"))
            if same_entity and (stamp - last_stamp).total_seconds() <= window_minutes * 60:
                group.append(event)
                placed = True
                break
        if not placed:
            groups.append([event])
    return groups


# Lab 7 improvement 2: do not treat prevented or change-approved activity as a malware signal.
APPROVED_CHANGE = re.compile(r"\bCHG-\d+\b", re.I)
MALWARE_TYPES = {"process_start", "credential_access", "file_quarantined"}


def is_benign_context(event: dict) -> bool:
    approved_change = bool(APPROVED_CHANGE.search(str(event.get("message", "")))) and "approved" in str(event.get("message", "")).lower()
    prevented = str(event.get("action", "")).lower() in {"blocked", "quarantined"} and event.get("event_type") in {"message_blocked", "file_quarantined"}
    return approved_change or prevented


def incident_features(group: list[dict]) -> dict[str, int]:
    sources = {event["source"] for event in group}
    types = {event["event_type"] for event in group}
    return {
        "ioc_match": int(any(event.get("ioc_match") for event in group)),
        "multi_source": int(len(sources) >= 2),
        "critical_asset": int(max((event.get("asset_criticality", 0) for event in group), default=0) >= 4),
        "privileged_identity": int(any(event.get("privileged_identity") for event in group)),
        "malware_signal": int(any(event["event_type"] in MALWARE_TYPES and not is_benign_context(event) and event["severity"] >= 60 for event in group)),
        "identity_anomaly": int(bool(types & {"mfa_method_added", "oauth_consent", "account_lockout"}) or sum(t == "login_failure" for t in [event["event_type"] for event in group]) >= 3),
        "exfil_signal": int("large_upload" in types),
    }


def score_group(group: list[dict]) -> tuple[int, dict]:
    features = incident_features(group)
    z = FEATURE_WEIGHTS["intercept"] + sum(FEATURE_WEIGHTS[k] * v for k, v in features.items())
    probability = 1 / (1 + math.exp(-z))
    max_sev = max(e["severity"] for e in group)
    score = round(100 * (0.7 * probability + 0.3 * (max_sev / 100)))
    return max(0, min(100, score)), {"features": features, "weights": FEATURE_WEIGHTS, "model_probability": round(probability, 4), "max_severity": max_sev}


def sanitize_untrusted_text(text: str) -> tuple[str, list[str]]:
    patterns = [r"ignore (all|any|the) previous", r"system prompt", r"execute (this|the) command", r"disable security", r"send .* secret", r"exfiltrat"]
    flags = [pattern for pattern in patterns if re.search(pattern, text, re.I)]
    cleaned = re.sub(r"[\r\n\t]+", " ", text)[:500]
    return cleaned, flags


def summarize(group: list[dict], score: int, explanation: dict) -> dict:
    messages = []
    flags = []
    for event in group:
        cleaned, found = sanitize_untrusted_text(str(event.get("message", "")))
        messages.append(cleaned)
        flags.extend(found)
    features = [name.replace("_", " ") for name, value in explanation["features"].items() if value]
    summary = f"Observed {len(group)} events across {len({e['source'] for e in group})} source(s). Risk score {score}/100. Evidence factors: {', '.join(features) or 'baseline telemetry only'}."
    return {"summary": summary, "untrusted_evidence_preview": messages[:3], "prompt_injection_flags": sorted(set(flags)), "advisory_only": True}


def severity_band(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def plan_actions(incident: dict) -> list[dict]:
    score = incident["risk_score"]
    actions = [{"action": "create_case", "approval_required": False, "dry_run": True, "reason": "Every correlated candidate receives an auditable case"}]
    if score >= 40:
        actions.append({"action": "notify_analyst", "approval_required": False, "dry_run": True, "reason": "Medium-or-higher candidates require human review"})
    if score >= 65:
        actions.append({"action": "collect_endpoint_triage", "approval_required": False, "dry_run": True, "reason": "Read-only evidence collection"})
    if score >= 85:
        features = incident.get("explanation", {}).get("features")
        # Lab 7 improvement 3: isolate a host only when there is endpoint-level evidence (legacy plans without features keep isolation).
        if features is None or features.get("malware_signal"):
            actions.append({"action": "isolate_endpoint", "approval_required": True, "dry_run": True, "reason": "High-impact containment action"})
        actions.append({"action": "disable_identity", "approval_required": True, "dry_run": True, "reason": "High-impact identity action"})
        if any(row.get("event_type") == "oauth_consent" for row in incident.get("evidence", [])):
            actions.append({"action": "revoke_oauth_grant", "approval_required": True, "dry_run": True, "reason": "Unverified OAuth consent must be revoked"})
    return actions


def append_hash_chain(records: list[dict]) -> list[dict]:
    previous = "GENESIS"
    output = []
    for record in records:
        payload = json.dumps(record, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256((previous + payload).encode()).hexdigest()
        enriched = dict(record, previous_hash=previous, record_hash=digest)
        output.append(enriched)
        previous = digest
    return output


def run_pipeline(dataset_root: Path, output_dir: Path, approval_token: str | None = None) -> list[dict]:
    assets = load_csv_index(dataset_root / "common" / "assets.csv", "hostname")
    identities = load_csv_index(dataset_root / "common" / "identities.csv", "user")
    indicators = parse_stix_indicators(dataset_root / "common" / "threat_intel_stix.json")
    event_file = dataset_root / "events.jsonl"
    if not event_file.exists():
        raise FileNotFoundError(f"Expected {event_file}")
    normalized = [normalize_event(row) for row in load_jsonl(event_file)]
    enriched = [enrich_event(row, assets, identities, indicators) for row in normalized]
    incidents = []
    audit = []
    for number, group in enumerate(correlate(enriched), 1):
        score, explanation = score_group(group)
        incident = {
            "incident_id": f"SOAR-{number:04d}",
            "event_ids": [row["event_id"] for row in group],
            "entities": {"users": sorted({row["user"] for row in group if row.get("user")}), "assets": sorted({row["asset"] for row in group if row.get("asset")})},
            "sources": sorted({row["source"] for row in group}),
            "evidence": [{key: row.get(key, "") for key in ("event_id", "timestamp", "source", "event_type", "user", "asset", "message", "src_ip", "dest_ip", "domain", "file_hash", "action", "severity")} for row in group],
            "risk_score": score,
            "severity": severity_band(score),
            "explanation": explanation,
        }
        incident["ai_assist"] = summarize(group, score, explanation)
        incident["planned_actions"] = plan_actions(incident)
        executed = []
        for action in incident["planned_actions"]:
            status = "simulated"
            if action["approval_required"] and approval_token != "INSTRUCTOR-APPROVED":
                status = "awaiting_approval"
            executed.append(dict(action, status=status, dry_run=True))
            audit.append({"timestamp": datetime.now(timezone.utc).isoformat(), "incident_id": incident["incident_id"], "event": "action_decision", "action": action["action"], "status": status, "dry_run": True})
        incident["actions"] = executed
        incidents.append(incident)
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json = lambda path, value: path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    write_json(output_dir / "incidents.json", incidents)
    chained = append_hash_chain(audit)
    (output_dir / "audit_log.jsonl").write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in chained), encoding="utf-8")
    return incidents
