"""Standard-library shell contract tests; start no workload."""
import json
from pathlib import Path
import subprocess
import unittest

EXPECTED = {
    "schema": "openclaw-smoke-v1",
    "status": "blocked",
    "reason": "portable_runtime_unavailable",
    "workload_started": False,
    "acceptance_verified": False,
}
SCRIPT = (Path(__file__).resolve().parent.parent / "scripts" / "run-smoke-test.sh").read_text(encoding="utf-8")


class SmokeTestEntry(unittest.TestCase):
    def cli(self, *args):
        # Deliberately provide no tool lookup path; no runtime authorization may
        # be inferred even if really named environment switches someday exist.
        return subprocess.run(
            ["/bin/sh", "-c", SCRIPT, "run-smoke-test.sh", *args],
            input=b"untrusted input must not be consumed\n",
            capture_output=True,
            timeout=3,
            env={"PATH": "", "OPENCLAW_RELEASE_AUTHORIZED": "true", "OPENCLAW_LAUNCHER": "/not/approved"},
            check=False,
        )

    def test_default_is_one_blocked_receipt(self):
        result = self.cli()
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertEqual(json.loads(result.stdout), EXPECTED)

    def test_help_is_not_acceptance(self):
        for arg in ("--help", "-h"):
            with self.subTest(arg=arg):
                result = self.cli(arg)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stderr, b"")
                self.assertIn(b"Usage:", result.stdout)
                self.assertNotIn(b'"status":', result.stdout)

    def test_no_launch_override_or_receipt_import(self):
        for args in (("--run",), ("--launcher=/not/approved",), ("--receipt=existing.json",),
                     ("--force",), ("",), ("--help", "--run"), ("untrusted-choice",)):
            with self.subTest(args=args):
                result = self.cli(*args)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"Usage:", result.stderr)
                self.assertNotIn(b"untrusted-choice", result.stderr)


if __name__ == "__main__":
    unittest.main()
