"""statsig x-statsig-id 生成测试。

覆盖:
  - 真签名核心算法 (用当前 build 实测黄金向量逐字符比对)
  - x0 兜底 (静态 / 动态)
  - 全局指纹配置解析 (完整 / 缺失 / 非法 -> 回退)
  - 顶层 statsig_id() 路由 (配齐走真签名, 缺前提走兜底)
  - headers.build_http_headers 透传 method/pathname

逆向结论见 docs/reverse/x-statsig-id-逆向分析.md。
"""
import base64
import importlib.util
import pathlib
import sys
import types
import unittest
from unittest.mock import patch

_ROOT = pathlib.Path(__file__).resolve().parents[1]


def _install_app_stubs() -> None:
    """注入 app.* 轻量桩, 让被测模块脱离完整依赖独立加载。"""
    logger_stub = types.SimpleNamespace(
        debug=lambda *a, **k: None,
        warning=lambda *a, **k: None,
        info=lambda *a, **k: None,
        error=lambda *a, **k: None,
    )
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
    sys.modules.setdefault(
        "app.dataplane.proxy.adapters", types.ModuleType("app.dataplane.proxy.adapters")
    )
    sys.modules["app.dataplane.proxy.adapters.profile"] = types.SimpleNamespace(
        ProxyProfile=object,
        resolve_proxy_profile=lambda lease: types.SimpleNamespace(
            user_agent="Mozilla/5.0 Chrome/136.0.0.0",
            browser="chrome136",
            cf_cookies="",
            cf_clearance="",
        ),
    )


def _load(mod_name: str, rel_path: str):
    file_path = _ROOT / rel_path
    spec = importlib.util.spec_from_file_location(mod_name, file_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


_install_app_stubs()
statsig = _load("test_statsig_module", "app/dataplane/proxy/adapters/statsig.py")
# headers 依赖 statsig: 让其 import 命中已加载的桩模块
sys.modules["app.dataplane.proxy.adapters.statsig"] = statsig
headers = _load("test_headers_module", "app/dataplane/proxy/adapters/headers.py")


# 当前 build (session D) 实测黄金向量 —— 页面网络层抓到的真实 94 字符签名
_GOLDEN = {
    "q_b64": "7cAxqu5OvS7cl7K6DL0Key3vtpbSwToW0ilvtKwmk/sPDSKtTZRkTWDLdvjMLNUB",
    "salt": (
        "obfiowerehiring6bd5740ccccccccccccd0"
        "999999999999980999999999999980ccccccccccccd00"
    ),
    "method": "GET",
    "pathname": "/rest/app-chat/conversations",
    "tf": 98271610,
    "r": 142,
    "expected": (
        "jmNOvyRgwDOgUhk8NIIzhPWjYTgYXE+0mFyn4ToiqB11gYOsI8Ma6sPuRfh2QqJ"
        "bj/QPVYsMnW08g+DvGEkYJ0lJ5ZXFjQ"
    ),
}


class _Cfg:
    """最小 ConfigSnapshot 桩。"""

    def __init__(self, values: dict | None = None):
        self._v = values or {}

    def get_str(self, key, default=""):
        return self._v.get(key, default)

    def get_bool(self, key, default=False):
        return self._v.get(key, default)


class RealSignatureTests(unittest.TestCase):
    def test_golden_vector_exact(self):
        """真签名给定相同 tf/r 与浏览器逐字符一致。"""
        q = base64.b64decode(_GOLDEN["q_b64"])
        got = statsig.gen_x_statsig_id(
            _GOLDEN["method"],
            _GOLDEN["pathname"],
            q,
            _GOLDEN["salt"],
            ts=_GOLDEN["tf"] + statsig.BASE_EPOCH,
            r=_GOLDEN["r"],
        )
        self.assertEqual(got, _GOLDEN["expected"])

    def test_signature_length_94(self):
        q = base64.b64decode(_GOLDEN["q_b64"])
        got = statsig.gen_x_statsig_id("POST", "/rest/x", q, _GOLDEN["salt"])
        self.assertEqual(len(got), 94)

    def test_bad_q_length_raises(self):
        with self.assertRaises(ValueError):
            statsig.gen_x_statsig_id("GET", "/x", b"\x00" * 10, _GOLDEN["salt"])


class FallbackTests(unittest.TestCase):
    def test_static_x0_decodes_to_childnodes(self):
        decoded = base64.b64decode(statsig.x0_fallback(dynamic=False)).decode()
        self.assertTrue(decoded.startswith("x0:TypeError:"))
        self.assertIn("childNodes", decoded)

    def test_dynamic_x0_is_x0_prefixed(self):
        with patch.object(statsig.random, "choice", return_value=True):
            decoded = base64.b64decode(statsig.x0_fallback(dynamic=True)).decode()
        self.assertTrue(decoded.startswith("x0:TypeError:"))


class FingerprintResolutionTests(unittest.TestCase):
    def test_complete_fingerprint(self):
        cfg = _Cfg({"statsig.q": _GOLDEN["q_b64"], "statsig.salt": _GOLDEN["salt"]})
        fp = statsig.resolve_statsig_fingerprint(cfg)
        self.assertTrue(fp.is_complete)
        self.assertEqual(len(fp.q), statsig.Q_LEN)

    def test_salt_prefix_autocompleted(self):
        # 只配 z(Q) 后缀, 自动补 obfiowerehiring 前缀
        suffix = _GOLDEN["salt"][len(statsig.SALT_PREFIX):]
        cfg = _Cfg({"statsig.q": _GOLDEN["q_b64"], "statsig.salt": suffix})
        fp = statsig.resolve_statsig_fingerprint(cfg)
        self.assertEqual(fp.salt, _GOLDEN["salt"])

    def test_missing_fields_incomplete(self):
        self.assertFalse(statsig.resolve_statsig_fingerprint(_Cfg({})).is_complete)

    def test_bad_base64_incomplete(self):
        cfg = _Cfg({"statsig.q": "!!!notb64!!!", "statsig.salt": _GOLDEN["salt"]})
        self.assertFalse(statsig.resolve_statsig_fingerprint(cfg).is_complete)

    def test_wrong_length_incomplete(self):
        short_q = base64.b64encode(b"\x00" * 10).decode()
        cfg = _Cfg({"statsig.q": short_q, "statsig.salt": _GOLDEN["salt"]})
        self.assertFalse(statsig.resolve_statsig_fingerprint(cfg).is_complete)


class TopLevelRoutingTests(unittest.TestCase):
    def _patch_cfg(self, values):
        return patch.object(statsig, "get_config", return_value=_Cfg(values))

    def test_real_when_configured(self):
        cfg = {
            "statsig.q": _GOLDEN["q_b64"],
            "statsig.salt": _GOLDEN["salt"],
            "statsig.mode": "real",
        }
        with self._patch_cfg(cfg):
            val = statsig.statsig_id("GET", "/rest/app-chat/conversations")
        # 真签名 94 字符, 不是 base64 编码的 x0 错误串
        self.assertEqual(len(val), 94)
        self.assertNotIn("x0:", base64.b64decode(val + "==", validate=False).decode("latin-1", "ignore"))

    def test_fallback_when_no_context(self):
        cfg = {"statsig.q": _GOLDEN["q_b64"], "statsig.salt": _GOLDEN["salt"]}
        with self._patch_cfg(cfg):
            val = statsig.statsig_id()  # 不给 method/pathname -> 兜底
        self.assertTrue(base64.b64decode(val).decode().startswith("x0:"))

    def test_fallback_when_fingerprint_missing(self):
        with self._patch_cfg({"statsig.mode": "real"}):
            val = statsig.statsig_id("GET", "/rest/x")
        self.assertTrue(base64.b64decode(val).decode().startswith("x0:"))

    def test_mode_fallback_forces_x0(self):
        cfg = {
            "statsig.q": _GOLDEN["q_b64"],
            "statsig.salt": _GOLDEN["salt"],
            "statsig.mode": "fallback",
        }
        with self._patch_cfg(cfg):
            val = statsig.statsig_id("GET", "/rest/app-chat/conversations")
        self.assertTrue(base64.b64decode(val).decode().startswith("x0:"))


class HeadersDelegationTests(unittest.TestCase):
    def test_build_http_headers_passes_context(self):
        captured = {}

        def _spy(method=None, pathname=None):
            captured["method"] = method
            captured["pathname"] = pathname
            return "STUB"

        with patch.object(headers, "statsig_id", _spy):
            h = headers.build_http_headers(
                "tok", method="GET", pathname="/rest/app-chat/conversations"
            )
        self.assertEqual(h["x-statsig-id"], "STUB")
        self.assertEqual(captured["method"], "GET")
        self.assertEqual(captured["pathname"], "/rest/app-chat/conversations")

    def test_build_http_headers_default_no_context(self):
        captured = {}

        def _spy(method=None, pathname=None):
            captured["method"] = method
            captured["pathname"] = pathname
            return "STUB"

        with patch.object(headers, "statsig_id", _spy):
            headers.build_http_headers("tok")
        self.assertIsNone(captured["method"])
        self.assertIsNone(captured["pathname"])


if __name__ == "__main__":
    unittest.main()
