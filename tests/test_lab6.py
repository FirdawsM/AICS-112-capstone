from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import idempotency_demo
from soar_lab.pipeline import enrich_event, plan_actions, run_pipeline

ROOT = Path(__file__).resolve().parent.parent


class Lab6Tests(unittest.TestCase):
    def test_low_confidence_ioc_is_not_a_match(self):
        event = {"event_id": "N1", "domain": "bad.example"}
        indicators = [{"value": "bad.example", "confidence": 40, "labels": ["phishing"]}]
        result = enrich_event(event, {}, {}, indicators)
        self.assertFalse(result["ioc_match"])

    def test_expired_ioc_is_not_a_match(self):
        # Known gap: enrich_event has no expiry check yet (see improvement backlog).
        event = {"event_id": "N2", "domain": "old.example"}
        indicators = [{"value": "old.example", "confidence": 95, "labels": ["phishing"], "valid_until": "2020-01-01T00:00:00Z"}]
        result = enrich_event(event, {}, {}, indicators)
        self.assertFalse(result["ioc_match"])

    def test_critical_plan_requires_approval(self):
        plan = plan_actions({"risk_score": 97})
        gated = {a["action"] for a in plan if a["approval_required"]}
        self.assertEqual(gated, {"isolate_endpoint", "disable_identity"})
        self.assertTrue(all(a["dry_run"] for a in plan))

    def test_critical_without_approval_stays_awaiting(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_pipeline(ROOT / "lab_data" / "training", Path(tmp))
            rows = [json.loads(line) for line in (Path(tmp) / "audit_log.jsonl").read_text().splitlines() if line.strip()]
        high = [r for r in rows if r["action"] in {"isolate_endpoint", "disable_identity"}]
        self.assertEqual(len(high), 2)
        self.assertTrue(all(r["status"] == "awaiting_approval" for r in high))

    def test_idempotency_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = idempotency_demo.LEDGER
            idempotency_demo.LEDGER = Path(tmp) / "ledger.json"
            try:
                first = idempotency_demo.run_action("SOAR-9", "HOST-1", "isolate_endpoint")
                second = idempotency_demo.run_action("SOAR-9", "HOST-1", "isolate_endpoint")
                other = idempotency_demo.run_action("SOAR-9", "user.x", "disable_identity")
            finally:
                idempotency_demo.LEDGER = original
        self.assertEqual((first, second, other), ("simulated", "already_completed", "simulated"))


if __name__ == "__main__":
    unittest.main()
