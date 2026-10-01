#!/usr/bin/env python3
"""Focused tests for ai_analyst.py — no real Ollama needed.

Most tests replace the module's HTTP layer with a fake that returns crafted
Ollama envelopes or raises, so behavior is deterministic. Two tests use a real
local HTTP server (redirect rejection, import side-effects).

    python3 -m unittest defense/test_ai_analyst.py -v
    (or)  cd defense && python3 -m unittest test_ai_analyst -v
"""
import json, os, sys, time, threading, unittest, socket
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ai_analyst
from ai_analyst import AIAnalyst, validate_incident, validate_output, IncidentError


GOOD_OUT = {"verdict": "likely_evil", "severity": 5, "summary": "Suspected evil twin.",
            "evidence": ["OPEN clone of a secured net"], "uncertainties": ["could be misconfig"],
            "recommended_action": "warn_user"}

INCIDENT = {"incident_id": "i1", "event_type": "evil_twin", "ssid": "PRV_GUEST",
            "bssid": "4e:49:6c:40:10:aa", "channel": 6, "rssi": -24, "crypto": ["OPEN"],
            "confidence": "HIGH", "reasons": ["foreign OUI", "43 dB louder"],
            "known_network": {"secured": True, "peak_rssi": -67}}


def envelope(content_obj):
    """Bytes of an Ollama /api/chat envelope whose content is content_obj (or raw str)."""
    content = content_obj if isinstance(content_obj, str) else json.dumps(content_obj)
    return json.dumps({"message": {"role": "assistant", "content": content}}).encode()


def wait_result(ai, iid, timeout=3):
    end = time.time() + timeout
    while time.time() < end:
        r = ai.get_result(iid)
        if r and r.get("status") in ("complete", "unavailable"):
            return r
        time.sleep(0.02)
    return ai.get_result(iid)


class FakeHTTP:
    """Callable stand-in for AIAnalyst._http_post with a scripted sequence."""
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = 0
    def __call__(self, url, data, timeout):
        self.calls += 1
        r = self.responses[min(self.calls - 1, len(self.responses) - 1)]
        if isinstance(r, Exception):
            raise r
        if callable(r):
            return r(url, data, timeout)
        return r


class InputValidationTests(unittest.TestCase):
    def test_sanitizes_and_drops_unknown(self):
        inc = validate_incident({**INCIDENT, "surprise": "x", "password": "secret"})
        self.assertNotIn("surprise", inc)
        self.assertNotIn("password", inc)
        self.assertEqual(inc["event_type"], "evil_twin")

    def test_rejects_missing_id(self):
        with self.assertRaises(IncidentError):
            validate_incident({"event_type": "evil_twin"})

    def test_rejects_bad_event_type(self):
        with self.assertRaises(IncidentError):
            validate_incident({"incident_id": "x", "event_type": "hack_now"})

    def test_truncates_oversized_strings(self):
        inc = validate_incident({"incident_id": "x", "event_type": "evil_twin",
                                 "ssid": "A" * 5000})
        self.assertLessEqual(len(inc["ssid"]), 64)

    def test_rejects_too_many_reasons(self):
        with self.assertRaises(IncidentError):
            validate_incident({"incident_id": "x", "event_type": "evil_twin",
                               "reasons": ["r"] * 50})


class OutputValidationTests(unittest.TestCase):
    def test_good(self):
        validate_output(dict(GOOD_OUT))

    def test_missing_field(self):
        bad = dict(GOOD_OUT); del bad["summary"]
        with self.assertRaises(ValueError):
            validate_output(bad)

    def test_unknown_field(self):
        with self.assertRaises(ValueError):
            validate_output({**GOOD_OUT, "extra": 1})

    def test_bad_enum_action(self):
        with self.assertRaises(ValueError):
            validate_output({**GOOD_OUT, "recommended_action": "launch_attack"})

    def test_bad_severity(self):
        with self.assertRaises(ValueError):
            validate_output({**GOOD_OUT, "severity": 9})

    def test_oversized_output_string(self):
        with self.assertRaises(ValueError):
            validate_output({**GOOD_OUT, "summary": "x" * 5000})


class BehaviorTests(unittest.TestCase):
    def _analyst(self, fake):
        ai = AIAnalyst(url="http://127.0.0.1:1", dedup_seconds=0.01)
        ai._http_post = fake
        return ai

    def test_valid_primary(self):
        ai = self._analyst(FakeHTTP(envelope(GOOD_OUT)))
        ai.start(warmup=False)
        ai.submit(INCIDENT)
        r = wait_result(ai, "i1")
        ai.stop()
        self.assertEqual(r["status"], "complete")
        self.assertEqual(r["model"], ai.primary)
        self.assertEqual(r["verdict"], "likely_evil")

    def test_primary_fail_then_fallback(self):
        ai = self._analyst(FakeHTTP(ConnectionError("down"), envelope(GOOD_OUT)))
        ai.start(warmup=False)
        ai.submit(INCIDENT)
        r = wait_result(ai, "i1")
        ai.stop()
        self.assertEqual(r["status"], "complete")
        self.assertEqual(r["model"], ai.fallback)

    def test_both_models_fail(self):
        ai = self._analyst(FakeHTTP(ConnectionError("a"), ConnectionError("b")))
        ai.start(warmup=False)
        ai.submit(INCIDENT)
        r = wait_result(ai, "i1")
        ai.stop()
        self.assertEqual(r["status"], "unavailable")
        self.assertEqual(r["error_code"], "all_models_failed")

    def test_malformed_json(self):
        ai = self._analyst(FakeHTTP(envelope("this is not json"), envelope("also bad")))
        ai.start(warmup=False)
        ai.submit(INCIDENT)
        r = wait_result(ai, "i1")
        ai.stop()
        self.assertEqual(r["status"], "unavailable")

    def test_schema_violation(self):
        bad = dict(GOOD_OUT); bad["recommended_action"] = "nuke"
        ai = self._analyst(FakeHTTP(envelope(bad), envelope(bad)))
        ai.start(warmup=False)
        ai.submit(INCIDENT)
        r = wait_result(ai, "i1")
        ai.stop()
        self.assertEqual(r["status"], "unavailable")

    def test_oversized_output(self):
        big = "x" * (70 * 1024)
        ai = self._analyst(FakeHTTP(envelope(big), envelope(big)))
        ai.start(warmup=False)
        ai.submit(INCIDENT)
        r = wait_result(ai, "i1")
        ai.stop()
        self.assertEqual(r["status"], "unavailable")

    def test_timeout(self):
        ai = self._analyst(FakeHTTP(socket.timeout("slow"), socket.timeout("slow")))
        ai.start(warmup=False)
        ai.submit(INCIDENT)
        r = wait_result(ai, "i1")
        ai.stop()
        self.assertEqual(r["status"], "unavailable")

    def test_oversized_input_rejected(self):
        ai = self._analyst(FakeHTTP(envelope(GOOD_OUT)))
        ai.start(warmup=False)
        res = ai.submit({"incident_id": "x", "event_type": "evil_twin", "reasons": ["r"] * 99})
        ai.stop()
        self.assertEqual(res["status"], "rejected")
        self.assertEqual(res["error_code"], "invalid_incident")

    def test_duplicate_suppressed(self):
        ai = AIAnalyst(url="http://127.0.0.1:1", dedup_seconds=60)
        ai._http_post = FakeHTTP(envelope(GOOD_OUT))
        ai.start(warmup=False)
        first = ai.submit(INCIDENT)
        second = ai.submit(INCIDENT)
        ai.stop()
        self.assertEqual(first["status"], "queued")
        self.assertEqual(second["status"], "suppressed")

    def test_queue_full(self):
        # don't start the worker, so the queue fills up
        ai = AIAnalyst(url="http://127.0.0.1:1", queue_size=2, dedup_seconds=0)
        r1 = ai.submit({**INCIDENT, "incident_id": "a"})
        r2 = ai.submit({**INCIDENT, "incident_id": "b"})
        r3 = ai.submit({**INCIDENT, "incident_id": "c"})
        self.assertEqual(r1["status"], "queued")
        self.assertEqual(r3["status"], "rejected")
        self.assertEqual(r3["error_code"], "queue_full")

    def test_callback_exception_isolated(self):
        ai = self._analyst(FakeHTTP(envelope(GOOD_OUT)))
        ai.start(warmup=False)
        ai.submit(INCIDENT, callback=lambda r: (_ for _ in ()).throw(RuntimeError("boom")))
        wait_result(ai, "i1")
        # worker must still be alive: a second job completes
        ai.submit({**INCIDENT, "incident_id": "i2"})
        r2 = wait_result(ai, "i2")
        ai.stop()
        self.assertEqual(r2["status"], "complete")

    def test_clean_shutdown(self):
        ai = self._analyst(FakeHTTP(envelope(GOOD_OUT)))
        ai.start(warmup=False)
        ai.stop()
        self.assertFalse(ai._running)
        self.assertFalse(ai._worker.is_alive())

    def test_cache_hit_second_time(self):
        ai = self._analyst(FakeHTTP(envelope(GOOD_OUT)))
        ai.start(warmup=False)
        ai.submit(INCIDENT); wait_result(ai, "i1")
        # same content, different id, past dedup window -> should be a cache hit (0 latency)
        time.sleep(0.02)
        ai.submit({**INCIDENT, "incident_id": "i1-again"})
        r = wait_result(ai, "i1-again")
        ai.stop()
        self.assertEqual(r["status"], "complete")
        self.assertEqual(r["latency_ms"], 0)
        self.assertGreaterEqual(ai.stats()["cache_hits"], 1)


class NetworkSafetyTests(unittest.TestCase):
    def test_reject_url_with_credentials(self):
        with self.assertRaises(ValueError):
            AIAnalyst(url="http://user:pass@host:11434")

    def test_reject_url_with_query(self):
        with self.assertRaises(ValueError):
            AIAnalyst(url="http://host:11434/?x=1")

    def test_redirect_is_rejected(self):
        # a local server that 302s -> _http_post must NOT follow it
        class Redir(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(302); self.send_header("Location", "http://evil.example/"); self.end_headers()
            def log_message(self, *a): pass
        srv = HTTPServer(("127.0.0.1", 0), Redir)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        port = srv.server_address[1]
        ai = AIAnalyst(url=f"http://127.0.0.1:{port}")
        with self.assertRaises(Exception):
            ai._http_post(ai.endpoint, b"{}", 3)
        srv.shutdown()


class ImportSideEffectTests(unittest.TestCase):
    def test_construct_starts_no_threads(self):
        before = threading.active_count()
        ai = AIAnalyst(url="http://127.0.0.1:1")
        self.assertEqual(threading.active_count(), before)  # no worker until start()
        self.assertIsNone(ai._worker)


if __name__ == "__main__":
    unittest.main(verbosity=2)
