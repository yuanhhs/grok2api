"""Real ``x-statsig-id`` signer bridge (persistent Node worker).

Runs ``scripts/x-statsig-id.js --serve`` as a single long-lived child process
and asks it to sign ``(pathname, method)`` per request. The worker self-fetches
and caches the grok homepage ``Q`` seed (proxy + cookie passed via env).

Design goals:
  * Never block the hot path on the slow parts. Spawn + first ``Q`` fetch happen
    in a background thread; until the worker is warm, ``get_statsig_id`` returns
    ``None`` so the caller falls back to the legacy ``_statsig_id`` (x0) value.
  * Never raise. Any failure (no node binary, dead worker, timeout, bad output)
    degrades silently to ``None`` → x0 fallback.

The fast path is one line written to stdin and one line read back from a
dedicated reader thread, dispatched by request id — single-digit milliseconds
once the worker is warm.
"""

import atexit
import base64
import json
import os
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

from app.platform.logging.logger import logger
from app.platform.config.snapshot import get_config
from app.control.proxy.config import resolve_clearance_config
from app.control.proxy.models import ProxyLease

# scripts/x-statsig-id.js relative to project root
# (app/dataplane/proxy/adapters/statsig.py → parents[4] == project root)
_SCRIPT = Path(__file__).resolve().parents[4] / "scripts" / "x-statsig-id.js"

_REQUEST_TIMEOUT_S = 1.5  # fast-path per-request deadline (warm worker)
_WARMUP_TIMEOUT_S = 60.0  # background warmup may include a homepage fetch
_SPAWN_COOLDOWN_S = 30.0  # avoid respawn thrash when node/Q is unavailable


def _egress_proxy(lease: ProxyLease | None = None) -> str:
    """First configured egress proxy (single_proxy url, else first of pool)."""
    if lease is not None and lease.proxy_url:
        return lease.proxy_url
    cfg = get_config()
    url = cfg.get_str("proxy.egress.proxy_url", "").strip()
    if url:
        return url
    for entry in cfg.get_list("proxy.egress.proxy_pool", []):
        if isinstance(entry, str) and entry.strip():
            return entry.strip()
    return ""


_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
)
_Q_TTL_S = 25 * 60     # refresh well within a grok build's lifetime
_Q_RETRY_S = 60        # retry sooner after a failed fetch


def _fetch_q(lease: ProxyLease | None = None) -> Optional[str]:
    """Fetch the grok homepage ``Q`` seed via browser-impersonating curl_cffi.

    This reuses the same TLS-fingerprint path the app's normal API calls use,
    so it passes Cloudflare — unlike the worker's plain-Node fetch, which CF
    challenges. Returns the 48-byte base64 ``<meta>`` seed, or ``None`` on any
    failure / CF challenge page. Runs in a background thread (blocking is fine).
    """
    try:
        from curl_cffi import requests as cffi
        from app.dataplane.proxy.adapters.profile import resolve_proxy_profile
        from app.dataplane.proxy.adapters.session import normalize_proxy_url
    except Exception as exc:
        logger.debug("statsig Q fetch: dependency unavailable: {}", exc)
        return None

    profile = resolve_proxy_profile(lease)  # validated browser + UA + cf_cookies
    impersonate = (profile.browser or "chrome").strip() or "chrome"
    headers = {
        "User-Agent": profile.user_agent or _DEFAULT_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if profile.cf_cookies:
        headers["Cookie"] = profile.cf_cookies

    cfg = get_config()
    proxy = _egress_proxy(lease)
    kwargs: dict = {"impersonate": impersonate, "headers": headers, "timeout": 20}
    if proxy:
        norm = normalize_proxy_url(proxy)
        kwargs["proxies"] = {"http": norm, "https": norm}
        if cfg.get_bool("proxy.egress.skip_ssl_verify", False):
            kwargs["verify"] = False

    try:
        resp = cffi.get("https://grok.com/", **kwargs)
        html = resp.text or ""
    except Exception as exc:
        logger.debug("statsig Q fetch failed: {}", exc)
        return None

    low = html.lower()
    if "just a moment" in low or "challenge-platform" in low:
        logger.debug(
            "statsig Q fetch: Cloudflare challenge (impersonate={} proxy={})",
            impersonate,
            "set" if proxy else "none",
        )
        return None
    for m in re.finditer(r'content="([^"]+)"', html):
        candidate = m.group(1)
        try:
            if len(base64.b64decode(candidate)) == 48:
                return candidate
        except Exception:
            pass
    logger.debug("statsig Q fetch: no 48-byte meta seed found in homepage")
    return None


class _Worker:
    """Single persistent Node signer process with id-keyed request dispatch."""

    def __init__(self) -> None:
        self._proc: Optional[subprocess.Popen] = None
        self._write_lock = threading.Lock()  # serialize stdin writes + counter
        self._pending_lock = threading.Lock()
        self._pending: dict[int, tuple[threading.Event, dict]] = {}
        self._counter = 0
        self._starting = False
        self._last_spawn = 0.0
        # Python-side Q cache (fetched via curl_cffi, fed to the worker).
        self._q: Optional[str] = None
        self._q_lock = threading.Lock()
        self._refresher_on = False
        self._last_lease: ProxyLease | None = None
        self._retry_on = False

    # -- lifecycle ---------------------------------------------------------

    def _alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def ensure_started(self, lease: ProxyLease | None = None) -> None:
        """Kick off a background spawn+warm if not already running/starting."""
        if lease is not None:
            self._remember_lease(lease)
        if self._alive() or self._starting:
            return
        now = time.monotonic()
        with self._write_lock:
            if self._alive() or self._starting:
                return
            if now - self._last_spawn < _SPAWN_COOLDOWN_S:
                return
            self._starting = True
            self._last_spawn = now
        threading.Thread(target=self._spawn_and_warm, daemon=True).start()

    def _remember_lease(self, lease: ProxyLease) -> None:
        if lease.cf_cookies or lease.user_agent or lease.proxy_url:
            self._last_lease = lease

    def _spawn_and_warm(self) -> None:
        try:
            lease = self._last_lease
            node_bin = get_config().get_str("statsig.node_bin", "node") or "node"
            env = os.environ.copy()
            proxy = _egress_proxy(lease)
            if proxy:
                env["HTTPS_PROXY"] = proxy
                env["ALL_PROXY"] = proxy
            cookie = (lease.cf_cookies if lease is not None else "") or resolve_clearance_config().cf_cookies
            if cookie:
                env["GROK_COOKIE"] = cookie

            logger.info(
                "statsig worker spawning: node_bin={} script={} proxy={} cf_cookie={}",
                node_bin,
                _SCRIPT.name,
                "set" if proxy else "none",
                "set" if cookie else "none",
            )
            proc = subprocess.Popen(
                [node_bin, str(_SCRIPT), "--serve"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                text=True,
                bufsize=1,
            )
            self._proc = proc
            threading.Thread(target=self._reader, args=(proc,), daemon=True).start()
            threading.Thread(target=self._stderr_drain, args=(proc,), daemon=True).start()

            # Fetch Q via browser-fingerprinted curl_cffi (passes Cloudflare),
            # then feed it to the worker — Node never touches CF itself.
            self._set_q(_fetch_q(lease))
            self._ensure_refresher()
            q = self._cached_q()
            if not q:
                logger.warning(
                    "statsig worker 预热失败: 无法获取 Q（Cloudflare 拦截 / curl_cffi 不可用 / 无 cf_clearance），"
                    "回滚到 x0 兼容串。可在 [proxy.clearance] 配 cf_cookies+user_agent 或 flaresolverr 提升过墙率。"
                )
                self._kill()
                self._schedule_retry()
                return

            sig, err = self._roundtrip(
                "/rest/app-chat/conversations/new", "POST", _WARMUP_TIMEOUT_S, q=q
            )
            if sig:
                logger.info(
                    "statsig worker ready: 真签名已生效 (sig_len={})", len(sig)
                )
            else:
                logger.warning(
                    "statsig worker 预热失败 (reason={})，回滚到 x0 兼容串。", err or "unknown"
                )
                self._kill()
                self._schedule_retry()
        except Exception as exc:
            logger.warning(
                "statsig worker 启动失败: {} (node 缺失/不可执行?)，回滚到 x0 兼容串", exc
            )
            self._kill()
            self._schedule_retry()
        finally:
            self._starting = False

    def _schedule_retry(self) -> None:
        with self._write_lock:
            if self._retry_on:
                return
            self._retry_on = True
        threading.Thread(target=self._retry_loop, daemon=True).start()

    def _retry_loop(self) -> None:
        time.sleep(_Q_RETRY_S)
        with self._write_lock:
            self._retry_on = False
        self.ensure_started(self._last_lease)

    def _kill(self) -> None:
        proc, self._proc = self._proc, None
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass

    # -- Q seed cache ------------------------------------------------------

    def _cached_q(self) -> Optional[str]:
        with self._q_lock:
            return self._q

    def _set_q(self, q: Optional[str]) -> None:
        if q:
            with self._q_lock:
                self._q = q

    def _ensure_refresher(self) -> None:
        with self._q_lock:
            if self._refresher_on:
                return
            self._refresher_on = True
        threading.Thread(target=self._refresh_q_loop, daemon=True).start()

    def _refresh_q_loop(self) -> None:
        """Periodically refresh Q so the hot path never blocks on a fetch."""
        while True:
            time.sleep(_Q_TTL_S)
            q = _fetch_q(self._last_lease)
            if q:
                self._set_q(q)

    # -- io ----------------------------------------------------------------

    def _reader(self, proc: subprocess.Popen) -> None:
        """Read response lines and dispatch to waiters by id until EOF."""
        try:
            stdout = proc.stdout
            assert stdout is not None
            while True:
                line = stdout.readline()
                if line == "":  # EOF — process exited
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except Exception:
                    continue
                rid = msg.get("id")
                with self._pending_lock:
                    slot = self._pending.pop(rid, None)
                if slot is not None:
                    slot[1]["msg"] = msg
                    slot[0].set()
        except Exception:
            pass
        finally:
            # Wake any stragglers so they fall back instead of hanging.
            with self._pending_lock:
                slots = list(self._pending.values())
                self._pending.clear()
            for event, _ in slots:
                event.set()

    def _stderr_drain(self, proc: subprocess.Popen) -> None:
        """Surface the Node worker's stderr (Q-fetch errors, ready banner)."""
        try:
            stderr = proc.stderr
            if stderr is None:
                return
            while True:
                line = stderr.readline()
                if line == "":
                    break
                line = line.rstrip()
                if line:
                    logger.debug("[statsig-worker] {}", line)
        except Exception:
            pass

    def _roundtrip(
        self, pathname: str, method: str, timeout: float, q: Optional[str] = None
    ) -> tuple[Optional[str], Optional[str]]:
        """Send one sign request. Returns ``(sig, err)`` — exactly one is set."""
        proc = self._proc
        if proc is None or proc.poll() is not None:
            return None, "worker not running"

        event = threading.Event()
        box: dict = {}
        with self._write_lock:
            if self._proc is None or self._proc.poll() is not None:
                return None, "worker not running"
            self._counter += 1
            rid = self._counter
            with self._pending_lock:
                self._pending[rid] = (event, box)
            try:
                req: dict = {"id": rid, "pathname": pathname, "method": method}
                if q:
                    req["q"] = q
                proc.stdin.write(json.dumps(req) + "\n")  # type: ignore[union-attr]
                proc.stdin.flush()  # type: ignore[union-attr]
            except Exception as exc:
                with self._pending_lock:
                    self._pending.pop(rid, None)
                self._kill()
                return None, f"stdin write failed: {exc}"

        if not event.wait(timeout):
            with self._pending_lock:
                self._pending.pop(rid, None)
            return None, f"timeout after {timeout}s"

        msg = box.get("msg")
        if not msg:
            return None, "worker exited / no response"
        sig = msg.get("sig")
        if isinstance(sig, str) and sig:
            return sig, None
        return None, str(msg.get("err") or "empty signature")

    def sign(
        self, pathname: str, method: str, lease: ProxyLease | None = None
    ) -> Optional[str]:
        if lease is not None:
            self._remember_lease(lease)
        if not self._alive():
            self.ensure_started(lease)
            logger.debug("statsig: worker 预热中,本次回滚 x0 (pathname={})", pathname)
            return None
        sig, err = self._roundtrip(
            pathname, method, _REQUEST_TIMEOUT_S, q=self._cached_q()
        )
        if sig is None:
            logger.debug(
                "statsig: 本次回滚 x0 (pathname={} reason={})", pathname, err
            )
        return sig


_worker = _Worker()
atexit.register(_worker._kill)


def get_statsig_id(
    pathname: str, method: str = "POST", lease: ProxyLease | None = None
) -> Optional[str]:
    """Return a real ``x-statsig-id`` for *pathname*/*method*, or ``None``.

    ``None`` means "fall back to x0" — returned whenever the real signer is
    disabled, not yet warm, unavailable, or slow. Never raises.
    """
    try:
        if not get_config().get_bool("features.real_statsig", True):
            logger.debug("statsig: real_statsig 已关闭 → 用 x0 兼容串")
            return None
        return _worker.sign(pathname or "/", (method or "POST").upper(), lease=lease)
    except Exception as exc:
        logger.debug("get_statsig_id error: {} → 用 x0 兼容串", exc)
        return None


__all__ = ["get_statsig_id"]
