"""Offline integration checks for distributed entrypoints; never test a live Mac."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
ENV = {
    "PATH": os.defpath,
    "LC_ALL": "C",
    # These values are not an approval channel. No real path or credential.
    "OPENCLAW_RELEASE_AUTHORIZED": "true",
    "OPENCLAW_PREFLIGHT_OK": "true",
    "OPENCLAW_LAUNCHER": "/bin/echo",
    "OPENCLAW_CONFIG": "/dev/null",
}


def invoke(name, *args):
    return subprocess.run(
        ["/bin/bash", str(SCRIPTS / name), *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=ENV.copy(),
        cwd=ROOT,
        timeout=5,
        check=False,
    )


def receipt(result):
    if result.stderr:
        raise AssertionError("unexpected diagnostic stream")
    if len(result.stdout.splitlines()) != 1:
        raise AssertionError("expected one JSON receipt")
    doc = json.loads(result.stdout)
    if type(doc) is not dict:
        raise AssertionError("expected a JSON object")
    return doc


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux-only offline entrypoint integration")
class Entrypoints(unittest.TestCase):
    def test_preflight_reports_unsupported_not_qualified(self):
        for args in ((), ("--json",)):
            with self.subTest(args=args):
                result = invoke("preflight.sh", *args)
                self.assertEqual(result.returncode, 1)
                obj = receipt(result)
                self.assertEqual(obj["schema"], "openclaw-preflight-v1")
                self.assertEqual(obj["status"], "blocked")
                self.assertEqual(obj["reason"], "unsupported_platform")
                for key in ("workload_started", "release_authorized", "security_qualified"):
                    self.assertIs(obj[key], False)

    def test_refused_preflight_is_not_a_smoke_result(self):
        pre = invoke("preflight.sh", "--json")
        self.assertEqual(receipt(pre)["status"], "blocked")
        smoke = invoke("run-smoke-test.sh")
        self.assertEqual(smoke.returncode, 3)
        self.assertEqual(receipt(smoke), {
            "schema": "openclaw-smoke-v1",
            "status": "blocked",
            "reason": "portable_runtime_unavailable",
            "workload_started": False,
            "acceptance_verified": False,
        })

    def test_smoke_rejects_executable_config_and_saved_receipts(self):
        for arg in ("--launcher=/bin/echo", "--config=/dev/null",
                    "--receipt=/dev/null", "--run", "--force",
                    "--fixture", "untrusted-choice"):
            with self.subTest(arg=arg):
                result = invoke("run-smoke-test.sh", arg)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"Usage:", result.stderr)
                self.assertNotIn(arg.encode("ascii"), result.stderr)

    def test_help_exit_zero_is_not_qualification(self):
        for script in ("preflight.sh", "run-smoke-test.sh"):
            with self.subTest(script=script):
                result = invoke(script, "--help")
                self.assertEqual(result.returncode, 0)
                self.assertNotIn(b'"acceptance_verified":true', result.stdout)
                self.assertNotIn(b'"security_qualified":true', result.stdout)
                self.assertNotIn(b'"workload_started":true', result.stdout)


if __name__ == "__main__":
    unittest.main()
