"""Ensure local smoke does not disclose credentials or clean unrelated state."""

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("container_smoke", ROOT / "ops/scripts/container_smoke.py")
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


class TestContainerSmoke(unittest.TestCase):
    def test_no_store_is_case_insensitive_and_required(self):
        smoke.require_no_store({"Cache-Control": "no-store", "Pragma": "no-cache"})
        for headers in ({}, {"cache-control": "no-store"}, {"cache-control": "public", "pragma": "no-cache"}):
            with self.subTest(headers=headers), self.assertRaises(RuntimeError):
                smoke.require_no_store(headers)

    def test_mint_never_returns_missing_or_non_string_token(self):
        for token in (None, "", 123):
            with patch.object(smoke, "request", return_value=({"access_token": token}, {"Cache-Control": "no-store", "Pragma": "no-cache"})):
                with self.assertRaises(RuntimeError):
                    smoke.mint("http://127.0.0.1:1234")

    def test_inactive_introspection_shape_is_exact(self):
        with patch.object(smoke, "request", return_value=({"active": False, "cause": "revoked"}, {"Cache-Control": "no-store", "Pragma": "no-cache"})):
            with self.assertRaises(RuntimeError):
                smoke.check_active("http://127.0.0.1:1234", "token", False)

    def test_failed_start_cleans_only_owned_container_and_volume(self):
        with patch.object(smoke, "docker", return_value="unused"), \
             patch.object(smoke, "wait_ready", side_effect=RuntimeError("startup failed")), \
             patch.object(smoke.subprocess, "run") as cleanup:
            with self.assertRaises(RuntimeError):
                smoke.run("example.invalid/sso:test")
        commands = [call.args[0] for call in cleanup.call_args_list]
        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[0][:3], ["docker", "rm", "--force"])
        self.assertTrue(commands[0][-1].startswith("snaplink-smoke-"))
        self.assertEqual(commands[1][:3], ["docker", "volume", "rm"])
        self.assertTrue(commands[1][-1].startswith("snaplink-smoke-state-"))
        self.assertNotIn("prune", str(commands))


if __name__ == "__main__":
    unittest.main()
