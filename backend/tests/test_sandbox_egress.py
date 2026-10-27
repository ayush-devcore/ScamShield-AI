import json
import socket
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy.dialects import postgresql

from app.db.models import User
from app.routes.sandbox import get_sandbox_job
from app.sandbox.analysis import analyze_observations
from app.sandbox.worker import execute_browser_job
from app.services.sandbox_runtime import decrypt_target, encrypt_target
from sandbox.proxy.egress_filter import DestinationDenied, pin_public_destination


class EgressPolicyTests(unittest.TestCase):
    def test_non_public_ipv4_ipv6_and_legacy_encodings_are_denied(self):
        denied = (
            ("127.0.0.1", 80), ("2130706433", 80), ("0177.0.0.1", 80),
            ("169.254.169.254", 80), ("100.64.0.1", 443), ("192.168.1.1", 80),
            ("0.0.0.0", 80), ("192.0.0.9", 80), ("224.0.0.1", 80), ("::1", 443),
            ("::ffff:127.0.0.1", 443), ("fe80::1", 443), ("fc00::1", 443),
            ("2001:db8::1", 443), ("64:ff9b::7f00:1", 443), ("2002:7f00:1::", 443),
        )
        for host, port in denied:
            with self.subTest(destination="redacted"):
                with self.assertRaises(DestinationDenied):
                    pin_public_destination(host, port)

    def test_nonstandard_ports_and_local_hostnames_are_denied(self):
        for host, port in (("example.com", 8080), ("host.docker.internal", 443), ("service.internal", 80), ("localhost", 80)):
            with self.subTest(destination="redacted"):
                resolver = lambda *_a, **_k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.2", port))]
                with self.assertRaises(DestinationDenied):
                    pin_public_destination(host, port, resolver=resolver)

    def test_public_dns_answers_are_validated_and_pinned(self):
        calls = []
        def resolver(host, port, **kwargs):
            calls.append((host, port))
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700:4700::1111", port, 0, 0)),
            ]
        pinned_ip, port, original_host = pin_public_destination("Example.COM.", 443, resolver=resolver)
        self.assertEqual(pinned_ip, "93.184.216.34")
        self.assertEqual(port, 443)
        self.assertEqual(original_host, "example.com")
        self.assertEqual(calls, [("example.com", 443)])

    def test_mixed_public_and_private_dns_answers_fail_closed(self):
        def rebinding_resolver(*_args, **_kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
            ]
        with self.assertRaises(DestinationDenied):
            pin_public_destination("rebind.example.org", 443, resolver=rebinding_resolver)

    def test_dns_rebinding_is_rechecked_for_each_connection(self):
        values = iter(("93.184.216.34", "10.0.0.2"))
        def resolver(_host, port, **_kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (next(values), port))]
        self.assertEqual(pin_public_destination("rebind.example.org", 443, resolver)[0], "93.184.216.34")
        with self.assertRaises(DestinationDenied):
            pin_public_destination("rebind.example.org", 443, resolver)


class SandboxAnalysisTests(unittest.TestCase):
    def test_findings_trace_back_to_real_observations(self):
        report = analyze_observations({
            "initial_origin": "http://start.example",
            "final_origin": "http://final.example",
            "navigation": {"http_status": 200},
            "forms": [{"action_origin": "https://collector.example", "method": "post"}],
            "download_attempt_count": 1,
            "requests": [],
        })
        self.assertEqual(report["classification"], "high")
        refs = {ref for finding in report["findings"] for ref in finding["observation_refs"]}
        self.assertTrue({"final_origin", "forms", "download_attempt_count"}.issubset(refs))
        self.assertIn("ruleset_version", report["method"])
        self.assertGreaterEqual(report["risk_score"], 60)

    def test_no_observed_rule_does_not_fabricate_findings(self):
        report = analyze_observations({"initial_origin": "https://example.com", "final_origin": "https://example.com", "forms": [], "download_attempt_count": 0})
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["risk_score"], 0)
        self.assertEqual(report["classification"], "safe")

    def test_form_on_redirected_final_origin_is_not_misclassified_as_cross_origin(self):
        report = analyze_observations({
            "initial_origin": "https://www.example.com",
            "final_origin": "https://example.com",
            "forms": [{"action_origin": "https://example.com", "method": "post"}],
            "download_attempt_count": 0,
        })
        self.assertEqual(report["findings"], [])


class DisposableWorkerTests(unittest.TestCase):
    @patch("docker.from_env")
    def test_worker_container_has_fixed_command_no_mounts_and_bounded_resources(self, from_env):
        import docker
        client = MagicMock()
        from_env.return_value = client
        client.images.get.return_value = SimpleNamespace(id="worker-image-id")
        client.networks.get.return_value = SimpleNamespace(attrs={"Internal": True})
        container = MagicMock()
        container.id = "container-id"
        client.containers.create.return_value = container
        client.api.exec_create.return_value = {"Id": "exec-id"}
        attached_socket = MagicMock()
        client.api.exec_start.return_value = attached_socket
        client.api.exec_inspect.return_value = {"ExitCode": 0}
        with patch("docker.utils.socket.frames_iter", return_value=[(1, json.dumps({"navigation": {"http_status": 200}}).encode()), (2, b"ignored")]):
            result = execute_browser_job("https://example.com/private?token=synthetic", uuid4())

        self.assertEqual(result["navigation"]["http_status"], 200)
        kwargs = client.containers.create.call_args.kwargs
        self.assertEqual(kwargs["user"], "pwuser")
        self.assertTrue(kwargs["read_only"])
        self.assertEqual(kwargs["cap_drop"], ["ALL"])
        self.assertEqual(kwargs["security_opt"], ["no-new-privileges:true"])
        self.assertEqual(kwargs["pids_limit"], 128)
        self.assertEqual(kwargs["network"], "scamshield-sandbox-internal")
        self.assertTrue(kwargs["auto_remove"])
        self.assertNotIn("volumes", kwargs)
        self.assertNotIn("/var/run/docker.sock", str(kwargs))
        self.assertNotIn("private", json.dumps(kwargs.get("environment", {})))
        self.assertEqual(kwargs["log_config"].type, "none")
        self.assertTrue(kwargs["command"][0] == "sleep")
        self.assertEqual(client.api.exec_create.call_args.kwargs["cmd"], ["python", "-I", "/opt/scamshield/sandbox_worker.py", "--stdin"])
        self.assertTrue(client.api.exec_create.call_args.kwargs["stdin"])
        self.assertIn(b"token=synthetic", attached_socket.sendall.call_args.args[0])
        attached_socket.close.assert_called_once()
        container.remove.assert_called_once_with(force=True, v=True)
        client.close.assert_called_once()


class SandboxAccessAndEncryptionTests(unittest.IsolatedAsyncioTestCase):
    async def test_job_lookup_is_scoped_to_authenticated_scan_owner(self):
        user = User(id=uuid4(), name="User", email="user@example.test", password_hash="x")
        class Result:
            def one_or_none(self):
                return None
        class Database:
            async def execute(self, statement):
                self.statement = statement
                return Result()
        db = Database()
        with self.assertRaises(HTTPException) as raised:
            await get_sandbox_job(uuid4(), user, db)
        self.assertEqual(raised.exception.status_code, 404)
        compiled = db.statement.compile(dialect=postgresql.dialect())
        self.assertIn("scans.user_id", str(compiled))
        self.assertIn(user.id, compiled.params.values())

    async def test_disabled_history_prevents_durable_job_creation(self):
        from app.routes.sandbox import submit_url_sandbox
        from app.schemas.sandbox import SandboxCapabilities, SandboxStatusResponse, SandboxUrlRequest
        user = User(id=uuid4(), name="User", email="user@example.test", password_hash="x")

        class Database:
            def __init__(self):
                self.added = False
            def add_all(self, _items):
                self.added = True
            async def commit(self):
                raise AssertionError("must not commit while history persistence is disabled")

        db = Database()
        available = SandboxStatusResponse(
            status="available", available=True, message="ready", reason=None,
            capabilities=SandboxCapabilities(url_browser_runtime=True, restricted_egress=True, file_static_analysis=False, file_detonation=False),
        )
        with patch("app.routes.sandbox.get_sandbox_status", return_value=available), \
             patch("app.routes.sandbox.scan_history_enabled", new=AsyncMock(return_value=False)), \
             patch("app.routes.sandbox.encrypt_target") as encrypt:
            with self.assertRaises(HTTPException) as raised:
                await submit_url_sandbox(SandboxUrlRequest(url="https://example.com/private?token=synthetic"), user, db)
        self.assertEqual(raised.exception.status_code, 409)
        self.assertFalse(db.added)
        encrypt.assert_not_called()

    async def test_queued_job_response_contains_only_encrypted_target_and_origin_preview(self):
        from cryptography.fernet import Fernet
        from app.core.config import settings
        from app.routes.sandbox import submit_url_sandbox
        from app.schemas.sandbox import SandboxCapabilities, SandboxStatusResponse, SandboxUrlRequest
        user = User(id=uuid4(), name="User", email="user@example.test", password_hash="x")

        class Database:
            def __init__(self):
                self.rows = []
            def add_all(self, rows):
                self.rows = rows
            async def commit(self):
                pass
            async def refresh(self, _item):
                pass

        db = Database()
        available = SandboxStatusResponse(
            status="available", available=True, message="ready", reason=None,
            capabilities=SandboxCapabilities(url_browser_runtime=True, restricted_egress=True, file_static_analysis=False, file_detonation=False),
        )
        original = settings.sandbox_encryption_key
        settings.sandbox_encryption_key = Fernet.generate_key().decode("ascii")
        try:
            with patch("app.routes.sandbox.get_sandbox_status", return_value=available), \
                 patch("app.routes.sandbox.scan_history_enabled", new=AsyncMock(return_value=True)):
                response = await submit_url_sandbox(SandboxUrlRequest(url="https://example.com/private?token=synthetic"), user, db)
            self.assertNotIn("synthetic", response.model_dump_json())
            scan, job = db.rows
            self.assertEqual(scan.redacted_preview, "https://example.com")
            self.assertIsNone(scan.input_hash)
            self.assertNotIn("synthetic", job.target_encrypted)
            self.assertEqual(job.state, "queued")
        finally:
            settings.sandbox_encryption_key = original

    async def test_encrypted_target_round_trip_uses_only_ciphertext_at_rest(self):
        from cryptography.fernet import Fernet
        from app.core.config import settings
        original = settings.sandbox_encryption_key
        settings.sandbox_encryption_key = Fernet.generate_key().decode("ascii")
        try:
            target = "https://example.com/reset?token=synthetic"
            encrypted = encrypt_target(target)
            self.assertNotIn("synthetic", encrypted)
            self.assertEqual(decrypt_target(encrypted), target)
        finally:
            settings.sandbox_encryption_key = original


if __name__ == "__main__":
    unittest.main()
