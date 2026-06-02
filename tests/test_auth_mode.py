"""Tests for Redfish authentication mode selection."""
import os
import sys
import types
import unittest
from unittest.mock import patch


class FakeMetric:
    """Minimal metric stand-in for importing collector modules."""

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def add_sample(self, *args, **kwargs):
        """Accept metric samples without storing them."""


prometheus_client = types.ModuleType("prometheus_client")
prometheus_core = types.ModuleType("prometheus_client.core")
prometheus_metrics_core = types.ModuleType("prometheus_client.metrics_core")
prometheus_core.GaugeMetricFamily = FakeMetric
prometheus_metrics_core.GaugeMetricFamily = FakeMetric
prometheus_metrics_core.CounterMetricFamily = FakeMetric
sys.modules.setdefault("prometheus_client", prometheus_client)
sys.modules.setdefault("prometheus_client.core", prometheus_core)
sys.modules.setdefault("prometheus_client.metrics_core", prometheus_metrics_core)
sys.modules.setdefault("OpenSSL", types.ModuleType("OpenSSL"))

from collector import RedfishMetricsCollector  # pylint: disable=wrong-import-position


class FakeResponse:
    """Small response object with the requests.Response methods used by collector."""

    def __init__(self, status_code=200, json_data=None, headers=None):
        self.status_code = status_code
        self._json_data = json_data or {}
        self.headers = headers or {}

    def __bool__(self):
        return self.status_code < 400

    def json(self):
        return self._json_data

    def raise_for_status(self):
        return None

    def close(self):
        return None


class FakeSession:
    """Fake requests session that records auth state for each request."""

    instances = []
    root_response = {
        "RedfishVersion": "1.16.0",
        "Systems": {"@odata.id": "/redfish/v1/Systems"},
        "SessionService": {"@odata.id": "/redfish/v1/SessionService"},
    }

    def __init__(self):
        self.auth = None
        self.verify = True
        self.headers = {}
        self.get_calls = []
        self.post_calls = []
        FakeSession.instances.append(self)

    @classmethod
    def reset(cls, root_response=None):
        cls.instances = []
        cls.root_response = root_response or {
            "RedfishVersion": "1.16.0",
            "Systems": {"@odata.id": "/redfish/v1/Systems"},
            "SessionService": {"@odata.id": "/redfish/v1/SessionService"},
        }

    def get(self, url, timeout=None):
        self.get_calls.append(
            {
                "url": url,
                "timeout": timeout,
                "auth": self.auth,
                "headers": dict(self.headers),
            }
        )
        if url.endswith("/redfish/v1"):
            return FakeResponse(json_data=FakeSession.root_response)
        if url.endswith("/redfish/v1/SessionService"):
            return FakeResponse(json_data={"Sessions": {"@odata.id": "/redfish/v1/Sessions"}})
        return FakeResponse(json_data={})

    def post(self, url, json=None, verify=None, timeout=None):
        self.post_calls.append(
            {
                "url": url,
                "json": json,
                "verify": verify,
                "timeout": timeout,
                "auth": self.auth,
                "headers": dict(self.headers),
            }
        )
        return FakeResponse(
            status_code=201,
            headers={
                "X-Auth-Token": "token-1",
                "Location": "/redfish/v1/Sessions/1",
            },
        )

    def close(self):
        return None


def make_collector(config=None):
    """Create a collector with stable target/user values."""
    return RedfishMetricsCollector(
        config or {},
        target="bmc.example.com",
        host="bmc.example.com",
        usr="admin",
        pwd="secret",
        metrics_type="health",
    )


class AuthModeTest(unittest.TestCase):
    """Auth mode behavior tests."""

    def setUp(self):
        FakeSession.reset()

    def test_basic_auth_mode_does_not_fetch_or_create_redfish_session(self):
        FakeSession.reset(
            {
                "RedfishVersion": "1.16.0",
                "Systems": {"@odata.id": "/redfish/v1/Systems"},
            }
        )

        with patch("collector.requests.Session", FakeSession):
            collector = make_collector({"auth_mode": "basic"})
            collector.get_session()

        session = FakeSession.instances[0]
        self.assertEqual(collector._auth_mode, "basic")
        self.assertTrue(collector._basic_auth)
        self.assertEqual(collector._redfish_up, 1)
        self.assertEqual(collector._auth_token, "")
        self.assertEqual(collector.urls["Systems"], "/redfish/v1/Systems")
        self.assertEqual(len(session.post_calls), 0)
        self.assertNotIn(
            "https://bmc.example.com/redfish/v1/SessionService",
            [call["url"] for call in session.get_calls],
        )
        self.assertEqual(session.get_calls[0]["auth"], ("admin", "secret"))

    def test_auth_mode_env_overrides_config(self):
        FakeSession.reset(
            {
                "RedfishVersion": "1.16.0",
                "Systems": {"@odata.id": "/redfish/v1/Systems"},
            }
        )

        with patch.dict(os.environ, {"AUTH_MODE": "basic"}):
            with patch("collector.requests.Session", FakeSession):
                collector = make_collector({"auth_mode": "session"})
                collector.get_session()

        session = FakeSession.instances[0]
        self.assertEqual(collector._auth_mode, "basic")
        self.assertEqual(len(session.post_calls), 0)
        self.assertEqual(collector._redfish_up, 1)

    def test_default_session_mode_creates_redfish_session(self):
        with patch("collector.requests.Session", FakeSession):
            collector = make_collector({})
            collector.get_session()

        session = FakeSession.instances[0]
        self.assertEqual(collector._auth_mode, "session")
        self.assertFalse(collector._basic_auth)
        self.assertEqual(collector._redfish_up, 1)
        self.assertEqual(collector._auth_token, "token-1")
        self.assertEqual(
            session.post_calls[0]["url"],
            "https://bmc.example.com/redfish/v1/Sessions",
        )
        self.assertIsNone(session.get_calls[0]["auth"])
        self.assertEqual(session.get_calls[1]["auth"], ("admin", "secret"))

    def test_basic_auth_request_removes_stale_token_header(self):
        with patch("collector.requests.Session", FakeSession):
            collector = make_collector({"auth_mode": "basic"})
            collector._auth_token = "stale-token"
            collector.connect_server("/redfish/v1")

        session = FakeSession.instances[0]
        self.assertEqual(session.get_calls[0]["auth"], ("admin", "secret"))
        self.assertNotIn("X-Auth-Token", session.get_calls[0]["headers"])


if __name__ == "__main__":
    unittest.main()
