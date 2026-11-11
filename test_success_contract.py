"""Offline regression tests. ALL responses/CAPTCHA values are SYNTHETIC fixtures.

No live site evidence is used. The Docker runner disables network access, mounts
only source/tests read-only, overrides the image entrypoint and supplies no env.
"""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import httpx

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("candidate_auto_signin_http", HERE / "auto_signin_http.py")
app = importlib.util.module_from_spec(spec)
# Do not read dotenv/configuration or inherit any account environment on import.
with patch.dict(os.environ, {}, clear=True), patch("dotenv.load_dotenv", return_value=False):
    spec.loader.exec_module(app)

INFO_PATH = "/cgi/v4/user/info"
SIGN_PATH = "/cgi/v4/user/sign"


class SyntheticGeeTest:
    """Protocol boundary fixture, NOT a real CAPTCHA solver."""

    def __init__(self, *args, **kwargs):
        pass

    def get_type(self):
        return {}

    def get_c_s(self):
        return None

    def ajax(self):
        return {}

    def get_pic(self, retry=0):
        return "nine", "https://synthetic.invalid/fixture.png"

    def verify(self, points):
        return {"status": "success", "data": {"result": "success", "validate": "SYNTHETIC_ONLY"}}

    def close(self):
        pass


class SuccessContractTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.output = self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
        self.stack.enter_context(patch.object(app, "GeeTestCrack", SyntheticGeeTest))
        self.stack.enter_context(patch.object(app, "_recognize_captcha", return_value=["1_1"]))
        self.stack.enter_context(patch.object(app, "OpenAI", side_effect=AssertionError("Paid API forbidden in offline tests")))
        self.stack.enter_context(patch.object(app, "login_with_redirects", side_effect=AssertionError("Real login forbidden in offline tests")))
        self.stack.enter_context(patch.object(app.time, "sleep", side_effect=AssertionError("Unexpected retry in synthetic fixture")))

    def client_for(self, sign_response, final_info, *, initial_info=None, info_status=200, sign_status=200, info_sequence=None):
        if initial_info is None:
            initial_info = {"sign": {"signed": False}}
        self.requests = []
        info_reads = 0

        def handle(request):
            nonlocal info_reads
            self.requests.append((request.method, request.url.path, request.url.query))
            if request.method == "GET" and request.url.path == INFO_PATH:
                info_reads += 1
                payload = (info_sequence[info_reads - 1] if info_sequence is not None
                           else initial_info if info_reads == 1 else final_info)
                return httpx.Response(info_status, json=payload)
            if request.method == "GET" and request.url.path == SIGN_PATH and request.url.query == b"gt":
                return httpx.Response(200, json={"gt": "SYNTHETIC_ONLY", "challenge": "SYNTHETIC_ONLY"})
            if request.method == "POST" and request.url.path == SIGN_PATH:
                return httpx.Response(sign_status, json=sign_response)
            raise AssertionError("Unexpected request outside synthetic HTTP fixture")

        client = httpx.Client(transport=httpx.MockTransport(handle))
        self.addCleanup(client.close)
        return client

    def main_exit(self, client, sign_success=None):
        self.stack.enter_context(patch.multiple(app, USERNAME="SYNTHETIC_ONLY", PASSWORD="SYNTHETIC_ONLY", CAPTCHA_API_KEY="SYNTHETIC_ONLY"))
        self.stack.enter_context(patch.object(app, "login_with_redirects", return_value=client))
        if sign_success is not None:
            self.stack.enter_context(patch.object(app, "sign_in", return_value=sign_success))
        try:
            app.main()
        except SystemExit as exc:
            return exc.code
        return 0

    def test_main_does_not_announce_success_when_final_state_unsigned(self):
        unsigned = {"sign": {"signed": False}}
        client = self.client_for({}, unsigned, initial_info=unsigned)
        self.main_exit(client, True)
        self.assertNotIn("✓ 签到成功!", self.output.getvalue())
        self.assertTrue(client.is_closed)

    def test_main_failure_returns_nonzero(self):
        for sign_success, signed in ((False, False), (False, True), (True, False)):
            with self.subTest(sign_success=sign_success, signed=signed):
                info = {"sign": {"signed": signed}}
                client = self.client_for({}, info, initial_info=info)
                self.assertNotEqual(self.main_exit(client, sign_success), 0)
                self.assertTrue(client.is_closed)

    def test_truthy_nonboolean_initial_signed_does_not_skip_submission(self):
        client = self.client_for(
            "SYNTHETIC ERROR: sign-in rejected", {"sign": {"signed": False}},
            initial_info={"sign": {"signed": "false"}},
        )
        self.assertIs(app.sign_in(client), False)
        self.assertEqual(sum(method == "POST" for method, _, _ in self.requests), 1)

    def test_verified_marker_after_final_confirmation_with_no_identity(self):
        for already_signed in (False, True):
            with self.subTest(already_signed=already_signed):
                self.output.seek(0)
                self.output.truncate()
                client = self.client_for(
                    "SYNTHETIC success text (not evidence)", {"sign": {"signed": True}},
                    initial_info={"sign": {"signed": already_signed}},
                )
                self.assertEqual(self.main_exit(client), 0)
                markers = [line for line in self.output.getvalue().splitlines() if line.startswith("SIGNIN_VERIFIED ")]
                self.assertEqual(len(markers), 1)
                self.assertEqual(json.loads(markers[0].split(" ", 1)[1]), {
                    "site": "sakurafrp", "signed": True, "already_signed": already_signed,
                })
                self.assertEqual(sum(method == "POST" for method, _, _ in self.requests), 0 if already_signed else 1)
                self.assertEqual(sum(method == "GET" and path == INFO_PATH for method, path, _ in self.requests), 2 if already_signed else 3)
                self.assertTrue(client.is_closed)

    def test_http_error_cannot_supply_verified_signed_state(self):
        info = {"sign": {"signed": True}}
        client = self.client_for({}, info, initial_info=info, info_status=500)
        self.assertEqual(self.main_exit(client, True), 1)
        self.assertNotIn("SIGNIN_VERIFIED ", self.output.getvalue())

    def test_error_string_is_not_success_while_final_state_unsigned(self):
        client = self.client_for("SYNTHETIC ERROR: sign-in rejected", {"sign": {"signed": False}})
        self.assertIs(app.sign_in(client), False)
        self.assertEqual(sum(method == "POST" for method, _, _ in self.requests), 1)

    def test_final_state_rejects_missing_malformed_or_nonboolean_signed(self):
        invalid_states = [None, [], "SYNTHETIC", {}, {"sign": None}, {"sign": []}, {"sign": {}}]
        invalid_states += [{"sign": {"signed": value}} for value in (False, None, 0, 1, "false", "true", [], {})]
        for final_info in invalid_states:
            with self.subTest(final_info=final_info):
                self.output.seek(0)
                self.output.truncate()
                client = self.client_for({}, final_info)
                self.assertEqual(self.main_exit(client, True), 1)
                self.assertNotIn("SIGNIN_VERIFIED ", self.output.getvalue())

    def test_string_text_alone_never_proves_success(self):
        for message in ("", "SYNTHETIC success", "SYNTHETIC error", "SYNTHETIC not successful"):
            with self.subTest(message=message):
                client = self.client_for(message, {"sign": {"signed": False}})
                self.assertIs(app.sign_in(client), False)

    def test_structured_response_still_requires_final_signed_state(self):
        for response, signed in (({"status": "success"}, False), ({"code": 0}, False), ({"code": 0}, True)):
            with self.subTest(response=response, signed=signed):
                self.output.seek(0)
                self.output.truncate()
                client = self.client_for(response, {"sign": {"signed": signed}})
                self.assertEqual(self.main_exit(client), 0 if signed else 1)
                self.assertEqual("SIGNIN_VERIFIED " in self.output.getvalue(), signed)

    def test_final_recheck_overrules_earlier_signed_confirmation(self):
        client = self.client_for(
            "SYNTHETIC success", {},
            info_sequence=[{"sign": {"signed": False}}, {"sign": {"signed": True}}, {"sign": {"signed": False}}],
        )
        self.assertEqual(self.main_exit(client), 1)
        self.assertNotIn("SIGNIN_VERIFIED ", self.output.getvalue())

    def test_cli_process_exit_codes_and_markers(self):
        for scenario, expected_code, already_signed in (("unsigned", 1, None), ("signed", 0, False), ("already", 0, True)):
            with self.subTest(scenario=scenario):
                result = subprocess.run(
                    [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--synthetic-cli", scenario],
                    capture_output=True, text=True, timeout=20,
                )
                self.assertEqual(result.returncode, expected_code, result.stderr)
                lines = result.stdout.splitlines()
                if expected_code:
                    self.assertEqual(lines, [])
                else:
                    self.assertEqual(len(lines), 1)
                    self.assertEqual(json.loads(lines[0].split(" ", 1)[1]), {
                        "site": "sakurafrp", "signed": True, "already_signed": already_signed,
                    })


def run_synthetic_cli(scenario):
    """Exercise real main/sign_in and OS exit propagation; all I/O is synthetic."""
    if scenario not in {"unsigned", "signed", "already"}:
        raise ValueError("Unknown synthetic scenario")
    case = SuccessContractTests()
    case.setUp()
    initial = {"sign": {"signed": scenario == "already"}}
    final = {"sign": {"signed": scenario != "unsigned"}}
    client = case.client_for("SYNTHETIC response: not success evidence", final, initial_info=initial)
    case.stack.enter_context(patch.multiple(app, USERNAME="SYNTHETIC_ONLY", PASSWORD="SYNTHETIC_ONLY", CAPTCHA_API_KEY="SYNTHETIC_ONLY"))
    case.stack.enter_context(patch.object(app, "login_with_redirects", return_value=client))
    try:
        app.main()
    finally:
        output = case.output.getvalue()
        case.doCleanups()
        for line in output.splitlines():
            if line.startswith("SIGNIN_VERIFIED "):
                print(line)


if __name__ == "__main__":
    if sys.argv[1:2] == ["--synthetic-cli"]:
        run_synthetic_cli(sys.argv[2])
    else:
        unittest.main()
