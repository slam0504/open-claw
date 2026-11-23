"""Offline pin-parser and completeness checks, with no engine or service."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "preflight.py"
SPEC = importlib.util.spec_from_file_location("openclaw_preflight", SOURCE)
PREFLIGHT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREFLIGHT)
DIGEST = "a" * 64


class Pins(unittest.TestCase):
    def document(self):
        return dict.fromkeys(PREFLIGHT.DIGEST_KEYS, DIGEST) | {
            "schema": PREFLIGHT.SCHEMA, "model_bytes": 32,
            "image_id": "sha256:" + DIGEST,
        }

    def check_document(self, raw, pin=None):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d).resolve() / "pins.json"
            p.write_bytes(raw)
            return PREFLIGHT.read_pins(str(p), pin or hashlib.sha256(raw).hexdigest(), DIGEST)

    def test_pin_requires_independently_matching_bytes(self):
        raw = json.dumps(self.document()).encode()
        self.assertEqual(self.check_document(raw), self.document())
        with self.assertRaises(PREFLIGHT.Refused):
            self.check_document(raw, "b" * 64)

    def test_duplicate_key_or_invalid_size_rejected(self):
        original = json.dumps(self.document())
        for raw in ('{"model_bytes":31,' + original[1:],
                    json.dumps(self.document() | {"model_bytes": True})):
            with self.subTest(raw=raw[:30]), self.assertRaises(PREFLIGHT.Refused):
                self.check_document(raw.encode())

    def evaluate(self, full):
        exe = str(Path(sys.executable))
        a = SimpleNamespace(
            python=exe, python_sha256=DIGEST, pins="/fake/pins", pins_sha256=DIGEST,
            node="/fake/node", runner="/fake/runner", template="/fake/template",
            model="/fake/model", docker_cli="/fake/docker", docker_socket="/fake/socket",
            docker_config="/fake/config", full_model_hash=full,
        )
        with patch.object(PREFLIGHT.sys, "version_info", (3, 13, 18)), \
             patch.object(PREFLIGHT, "regular") as regular, \
             patch.object(PREFLIGHT, "read_pins", return_value=self.document()), \
             patch.object(PREFLIGHT, "node_at"), patch.object(PREFLIGHT, "engine_check"), \
             patch.object(PREFLIGHT, "check_ports"):
            result = PREFLIGHT.assess(a)
            model_reads = [
                x.kwargs["digest"] for x in regular.call_args_list
                if x.args and str(x.args[0]) == a.model
            ]
        self.assertEqual(len(model_reads), 1)
        return result, model_reads[0]

    def test_header_only_never_counts_as_full_model_verification(self):
        (status, _, rows, code), digest = self.evaluate(False)
        self.assertEqual((status, code, rows["model"]), ("incomplete", 2, "header_size_only"))
        self.assertIsNone(digest)

    def test_full_model_opt_in_supplies_expected_digest(self):
        (status, reason, rows, code), digest = self.evaluate(True)
        self.assertEqual((status, reason, code, rows["model"]),
                         ("checks_passed", "read_only_inventory", 0, "pass"))
        self.assertEqual(digest, DIGEST)


if __name__ == "__main__":
    unittest.main()
