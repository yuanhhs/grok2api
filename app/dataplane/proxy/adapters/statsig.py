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
import json
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

from app.platform.logging.logger import logger
from app.platform.config.snapshot import get_config
from app.control.proxy.config import resolve_clearance_config

# scripts/x-statsig-id.js relative to project root
# (app/dataplane/proxy/adapters/statsig.py → parents[4] == project root)
_SCRIPT = Path(__file__).resolve().parents[4] / "scripts" / "x-statsig-id.js"

_REQUEST_TIMEOUT_S = 1.5  # fast-path per-request deadline (warm worker)
_WARMUP_TIMEOUT_S = 60.0  # background warmup may include a homepage fetch
_SPAWN_COOLDOWN_S = 30.0  # avoid respawn thrash when node/Q is unavailable


def _egress_proxy() -> str:
    """First configured egress proxy (single_proxy url, else first of pool)."""
    cfg = get_config()
    url = cfg.get_str("proxy.egress.proxy_url", "").strip()
    if url:
        return url
    for entry in cfg.get_list("proxy.egress.proxy_pool", []):
        if isinstance(entry, str) and entry.strip():
            return entry.strip()
    return ""


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

    # -- lifecycle ---------------------------------------------------------

    def _alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def ensure_started(self) -> None:
        """Kick off a background spawn+warm if not already running/starting."""
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

    def _spawn_and_warm(self) -> None:
        try:
            node_bin = get_config().get_str("statsig.node_bin", "node") or "node"
            env = os.environ.copy()
            proxy = _egress_proxy()
            if proxy:
                env["HTTPS_PROXY"] = proxy
                env["ALL_PROXY"] = proxy
            cookie = resolve_clearance_config().cf_cookies
            if cookie:
                env["GROK_COOKIE"] = cookie

            proc = subprocess.Popen(
                [node_bin, str(_SCRIPT), "--serve"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=env,
                text=True,
                bufsize=1,
            )
            self._proc = proc
            threading.Thread(target=self._reader, args=(proc,), daemon=True).start()

            # Warmup also forces the worker's first Q fetch; give it room.
            warm = self._roundtrip(
                "/rest/app-chat/conversations/new", "POST", _WARMUP_TIMEOUT_S
            )
            if warm:
                logger.debug("statsig worker ready (sig_len={})", len(warm))
            else:
                logger.debug("statsig worker warmup produced no signature; using x0 fallback")
                self._kill()
        except Exception as exc:
            logger.debug("statsig worker spawn failed: {}", exc)
            self._kill()
        finally:
            self._starting = False

    def _kill(self) -> None:
        proc, self._proc = self._proc, None
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass

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

    def _roundtrip(self, pathname: str, method: str, timeout: float) -> Optional[str]:
        proc = self._proc
        if proc is None or proc.poll() is not None:
            return None

        event = threading.Event()
        box: dict = {}
        with self._write_lock:
            if self._proc is None or self._proc.poll() is not None:
                return None
            self._counter += 1
            rid = self._counter
            with self._pending_lock:
                self._pending[rid] = (event, box)
            try:
                payload = json.dumps(
                    {"id": rid, "pathname": pathname, "method": method}
                )
                proc.stdin.write(payload + "\n")  # type: ignore[union-attr]
                proc.stdin.flush()  # type: ignore[union-attr]
            except Exception:
                with self._pending_lock:
                    self._pending.pop(rid, None)
                self._kill()
                return None

        if not event.wait(timeout):
            with self._pending_lock:
                self._pending.pop(rid, None)
            return None

        msg = box.get("msg")
        if not msg:
            return None
        sig = msg.get("sig")
        return sig if isinstance(sig, str) and sig else None

    def sign(self, pathname: str, method: str) -> Optional[str]:
        if not self._alive():
            self.ensure_started()
            return None
        return self._roundtrip(pathname, method, _REQUEST_TIMEOUT_S)


_worker = _Worker()
atexit.register(_worker._kill)


def get_statsig_id(pathname: str, method: str = "POST") -> Optional[str]:
    """Return a real ``x-statsig-id`` for *pathname*/*method*, or ``None``.

    ``None`` means "fall back to x0" — returned whenever the real signer is
    disabled, not yet warm, unavailable, or slow. Never raises.
    """
    try:
        if not get_config().get_bool("features.real_statsig", True):
            return None
        return _worker.sign(pathname or "/", (method or "POST").upper())
    except Exception as exc:
        logger.debug("get_statsig_id error: {}", exc)
        return None


__all__ = ["get_statsig_id"]
