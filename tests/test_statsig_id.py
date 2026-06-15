import base64
import importlib.util
import pathlib
import sys
import types
import unittest
from unittest.mock import patch


def _load_headers_module():
    logger_stub = types.SimpleNamespace(debug=lambda *args, **kwargs: None)
    sys.modules.setdefault("app", types.ModuleType("app"))
    sys.modules.setdefault("app.platform", types.ModuleType("app.platform"))
    sys.modules.setdefault("app.platform.logging", types.ModuleType("app.platform.logging"))
    sys.modules["app.platform.logging.logger"] = types.SimpleNamespace(logger=logger_stub)
    sys.modules.setdefault("app.platform.config", types.ModuleType("app.platform.config"))
    sys.modules["app.platform.config.snapshot"] = types.SimpleNamespace(get_config=lambda: None)
    sys.modules.setdefault("app.control", types.ModuleType("app.control"))
    sys.modules.setdefault("app.control.proxy", types.ModuleType("app.control.proxy"))
    sys.modules["app.control.proxy.models"] = types.SimpleNamespace(ProxyLease=object)
    sys.modules.setdefault("app.dataplane", types.ModuleType("app.dataplane"))
    sys.modules.setdefault("app.dataplane.proxy", types.ModuleType("app.dataplane.proxy"))
    sys.modules.setdefault("app.dataplane.proxy.adapters", types.ModuleType("app.dataplane.proxy.adapters"))
    sys.modules["app.dataplane.proxy.adapters.profile"] = types.SimpleNamespace(
        ProxyProfile=object,
        resolve_proxy_profile=lambda lease: None,
    )

    file_path = pathlib.Path(__file__).resolve().parents[1] / "app/dataplane/proxy/adapters/headers.py"
    spec = importlib.util.spec_from_file_location("test_headers_module", file_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


headers = _load_headers_module()


class _DummyConfig:
    def __init__(self, real_statsig=False, dynamic_statsig=True):
        self._real = real_statsig
        self._dynamic = dynamic_statsig

    def get_bool(self, key, default=False):
        if key == "features.dynamic_statsig":
            return self._dynamic
        if key == "features.real_statsig":
            return self._real
        return default


_PROFILE = types.SimpleNamespace(
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    browser="chrome120",
    cf_cookies="",
    cf_clearance="",
)


def _build_headers(real_statsig, url=None, method="POST"):
    # dynamic_statsig off → fallback is the deterministic static x0 value.
    cfg = _DummyConfig(real_statsig=real_statsig, dynamic_statsig=False)
    with patch.object(headers, "get_config", return_value=cfg):
        with patch.object(headers, "_resolve_profile", return_value=_PROFILE):
            return headers.build_http_headers("tok", url=url, method=method)


class StatsigIdTests(unittest.TestCase):
    def test_dynamic_statsig_uses_x1_prefix(self):
        with patch.object(headers, "get_config", return_value=_DummyConfig()):
            with patch.object(headers.random, "choice", return_value=True):
                value = headers._statsig_id()

        decoded = base64.b64decode(value).decode()
        self.assertTrue(decoded.startswith("x1:TypeError:"))

    def test_real_statsig_disabled_falls_back_to_x0(self):
        """url provided but real_statsig off → never queries signer, uses x0."""
        hdrs = _build_headers(
            False, url="https://grok.com/rest/app-chat/conversations/new"
        )
        decoded = base64.b64decode(hdrs["x-statsig-id"]).decode()
        self.assertTrue(decoded.startswith("e:TypeError:"))  # static x0 default

    def test_real_statsig_uses_signer_when_available(self):
        """real_statsig on + signer returns a value → that value is used verbatim."""
        sentinel = "REAL_SIGNATURE_VALUE"
        statsig_stub = types.SimpleNamespace(
            get_statsig_id=lambda path, method, **kwargs: sentinel
        )
        sys.modules["app.dataplane.proxy.adapters.statsig"] = statsig_stub
        try:
            hdrs = _build_headers(
                True, url="https://grok.com/rest/app-chat/conversations/new"
            )
            self.assertEqual(hdrs["x-statsig-id"], sentinel)
        finally:
            sys.modules.pop("app.dataplane.proxy.adapters.statsig", None)

    def test_real_statsig_signer_none_falls_back_to_x0(self):
        """real_statsig on but signer returns None (not warm/failed) → x0 fallback."""
        statsig_stub = types.SimpleNamespace(
            get_statsig_id=lambda path, method, **kwargs: None
        )
        sys.modules["app.dataplane.proxy.adapters.statsig"] = statsig_stub
        try:
            hdrs = _build_headers(
                True, url="https://grok.com/rest/app-chat/conversations/new"
            )
            decoded = base64.b64decode(hdrs["x-statsig-id"]).decode()
            self.assertTrue(decoded.startswith("e:TypeError:"))
        finally:
            sys.modules.pop("app.dataplane.proxy.adapters.statsig", None)

    def test_no_url_never_queries_signer(self):
        """Callers that omit url always use x0, regardless of real_statsig."""
        def _boom(*a, **k):
            raise AssertionError("signer must not be called without url")

        statsig_stub = types.SimpleNamespace(get_statsig_id=_boom)
        sys.modules["app.dataplane.proxy.adapters.statsig"] = statsig_stub
        try:
            hdrs = _build_headers(True, url=None)
            self.assertIn("x-statsig-id", hdrs)
        finally:
            sys.modules.pop("app.dataplane.proxy.adapters.statsig", None)


if __name__ == "__main__":
    unittest.main()
