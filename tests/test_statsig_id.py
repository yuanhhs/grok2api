import asyncio
import importlib.util
import pathlib
import sys
import types
import unittest
from unittest.mock import AsyncMock, patch


def _load_statsig_module():
    for mod in [
        "app", "app.platform", "app.platform.logging",
    ]:
        sys.modules.setdefault(mod, types.ModuleType(mod))
    sys.modules["app.platform.logging.logger"] = types.SimpleNamespace(
        logger=types.SimpleNamespace(
            debug=lambda *a, **k: None,
            warning=lambda *a, **k: None,
            info=lambda *a, **k: None,
        )
    )
    file_path = (
        pathlib.Path(__file__).resolve().parents[1]
        / "app/dataplane/proxy/adapters/statsig.py"
    )
    spec = importlib.util.spec_from_file_location("test_statsig_module", file_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


statsig = _load_statsig_module()

_FALLBACK = (
    "ZTpUeXBlRXJyb3I6IENhbm5vdCByZWFkIHByb3BlcnRpZXMgb2YgdW5kZWZpbmVkIChyZWFkaW5nICdjaGls"
    "ZE5vZGVzJyk="
)


class StatsigSignTests(unittest.IsolatedAsyncioTestCase):
    async def test_sign_returns_non_empty_string(self):
        fake_q = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        result = await statsig.sign("/rest/app-chat/conversations/new", "POST", fake_q)
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 10)

    async def test_statsig_id_falls_back_on_q_failure(self):
        async def _bad_q(*a, **k):
            raise RuntimeError("no Q")

        with patch.object(statsig, "get_q", side_effect=_bad_q):
            result = await statsig.statsig_id("/rest/app-chat/conversations/new", "POST")
        self.assertEqual(result, _FALLBACK)

    async def test_statsig_id_uses_signed_value_when_q_available(self):
        fake_q = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

        async def _good_q(*a, **k):
            return fake_q

        with patch.object(statsig, "get_q", side_effect=_good_q):
            result = await statsig.statsig_id("/rest/app-chat/conversations/new", "POST")
        self.assertNotEqual(result, _FALLBACK)
        self.assertGreater(len(result), 10)


if __name__ == "__main__":
    unittest.main()
