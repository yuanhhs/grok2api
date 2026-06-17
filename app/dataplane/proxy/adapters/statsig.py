"""Statsig x-statsig-id signing via bundled Node.js signer.

Calls scripts/x-statsig-id.js as a subprocess to produce a real x-statsig-id
value.  Q (the 48-byte base64 site-verification meta) is fetched once from
grok.com and cached in-process; it is refreshed automatically when the cache
is older than CACHE_TTL seconds or when the caller signals a stale Q.
"""

import asyncio
import base64
import re
import time
import os
import pathlib
from typing import Optional

from app.platform.logging.logger import logger

_SCRIPT = pathlib.Path(__file__).resolve().parents[4] / "scripts" / "x-statsig-id.js"

_CACHE_TTL = 3600.0  # seconds before Q is re-fetched

_q: Optional[str] = None
_q_ts: float = 0.0
_q_lock: Optional[asyncio.Lock] = None


def _get_lock() -> asyncio.Lock:
    global _q_lock
    if _q_lock is None:
        _q_lock = asyncio.Lock()
    return _q_lock


async def _fetch_q_html(cookie: str, proxy_url: str) -> str:
    """Fetch grok.com homepage HTML using curl_cffi to bypass Cloudflare."""
    from curl_cffi.requests import AsyncSession

    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/142.0.0.0 Safari/537.36"
        ),
    }
    if cookie:
        headers["Cookie"] = cookie

    kwargs: dict = {"headers": headers, "timeout": 20, "impersonate": "chrome142"}
    if proxy_url:
        kwargs["proxy"] = proxy_url

    async with AsyncSession() as s:
        resp = await s.get("https://grok.com/", **kwargs)
        return resp.text


def _extract_q(html: str) -> Optional[str]:
    for m in re.finditer(r'content="([^"]+)"', html):
        c = m.group(1)
        try:
            if len(base64.b64decode(c)) == 48:
                return c
        except Exception:
            pass
    return None


async def fetch_q(cookie: str = "", proxy_url: str = "") -> str:
    """Fetch a fresh Q from grok.com homepage.  Raises on failure."""
    html = await _fetch_q_html(cookie, proxy_url)
    if re.search(r"just a moment|challenge-platform", html, re.IGNORECASE):
        raise RuntimeError(
            "Cloudflare challenge page returned — cf_clearance cookie may be expired"
        )
    q = _extract_q(html)
    if not q:
        raise RuntimeError("Could not find 48-byte meta Q in grok.com homepage")
    return q


async def get_q(cookie: str = "", proxy_url: str = "") -> str:
    """Return a cached Q, refreshing if stale."""
    global _q, _q_ts
    lock = _get_lock()
    if _q and (time.monotonic() - _q_ts) < _CACHE_TTL:
        return _q
    async with lock:
        if _q and (time.monotonic() - _q_ts) < _CACHE_TTL:
            return _q
        try:
            _q = await fetch_q(cookie=cookie, proxy_url=proxy_url)
            _q_ts = time.monotonic()
            logger.debug("statsig Q refreshed")
        except Exception as exc:
            logger.warning("statsig Q fetch failed: {} — will retry next call", exc)
            if _q:
                return _q
            raise
    return _q


async def sign(pathname: str, method: str, q: str) -> str:
    """Run x-statsig-id.js and return the signed header value."""
    env = {**os.environ, "MSYS_NO_PATHCONV": "1"}
    proc = await asyncio.create_subprocess_exec(
        "node",
        str(_SCRIPT),
        pathname,
        method,
        q,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
    if proc.returncode != 0:
        err = stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"x-statsig-id.js rc={proc.returncode}: {err}")
    result = stdout.decode("utf-8", "replace").strip()
    if not result:
        raise RuntimeError("x-statsig-id.js returned empty output")
    return result


async def statsig_id(pathname: str, method: str, cookie: str = "", proxy_url: str = "") -> str:
    """High-level: resolve Q then sign and return the x-statsig-id value.

    Falls back to the legacy static value on any error so callers always get a
    header value.
    """
    _FALLBACK = (
        "ZTpUeXBlRXJyb3I6IENhbm5vdCByZWFkIHByb3BlcnRpZXMgb2YgdW5kZWZpbmVkIChyZWFkaW5nICdjaGls"
        "ZE5vZGVzJyk="
    )
    try:
        q = await get_q(cookie=cookie, proxy_url=proxy_url)
        return await sign(pathname, method, q)
    except Exception as exc:
        logger.warning("statsig_id failed ({}), using fallback", exc)
        return _FALLBACK


__all__ = ["statsig_id", "fetch_q", "get_q", "sign"]
