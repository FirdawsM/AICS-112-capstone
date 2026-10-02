import hashlib
import json
from pathlib import Path

PLAYBOOK_VERSION = "1.0.0"
LEDGER = Path("evidence/idempotency_ledger.json")


def key(incident_id: str, entity_id: str, action: str) -> str:
    raw = f"{PLAYBOOK_VERSION}|{incident_id}|{entity_id}|{action}"
    return hashlib.sha256(raw.encode()).hexdigest()


def run_action(incident_id: str, entity_id: str, action: str) -> str:
    ledger = json.loads(LEDGER.read_text()) if LEDGER.exists() else {}
    k = key(incident_id, entity_id, action)
    if k in ledger:
        return "already_completed"
    ledger[k] = {"incident_id": incident_id, "entity_id": entity_id, "action": action, "status": "simulated", "dry_run": True}
    LEDGER.parent.mkdir(exist_ok=True)
    LEDGER.write_text(json.dumps(ledger, indent=2) + "\n")
    return "simulated"


if __name__ == "__main__":
    print("first call :", run_action("SOAR-0001", "FIN-LT-044", "isolate_endpoint"))
    print("second call:", run_action("SOAR-0001", "FIN-LT-044", "isolate_endpoint"))
    print("other action:", run_action("SOAR-0001", "amina.bello", "disable_identity"))
