"""Shared helper: map an UpstreamError to the correct ProxyFeedbackKind.

All transport modules (assets, media, livekit, imagine_ws …) use this so the
mapping stays consistent and clearance bundles are properly invalidated.

Rules
-----
401  → UNAUTHORIZED  (invalidates clearance bundle)
403  → CHALLENGE     (invalidates clearance bundle — treat all 403s as potential CF)
429  → RATE_LIMITED
≥500 → UPSTREAM_5XX
else → TRANSPORT_ERROR
"""

from app.platform.errors import UpstreamError
from app.control.proxy.models import ProxyFeedback, ProxyFeedbackKind
from app.platform.logging.logger import logger


def upstream_feedback(exc: UpstreamError) -> ProxyFeedback:
    """Return a ``ProxyFeedback`` for an ``UpstreamError`` response."""
    status = exc.status or 0
    if status == 401:
        kind = ProxyFeedbackKind.UNAUTHORIZED
    elif status == 403:
        kind = ProxyFeedbackKind.CHALLENGE
    elif status == 429:
        kind = ProxyFeedbackKind.RATE_LIMITED
    elif status >= 500:
        kind = ProxyFeedbackKind.UPSTREAM_5XX
    else:
        kind = ProxyFeedbackKind.TRANSPORT_ERROR
    return ProxyFeedback(kind=kind, status_code=status or None)


async def safe_proxy_feedback(proxy, lease, feedback: ProxyFeedback, *, context: str = "") -> None:
    """Send proxy feedback without letting feedback failures mask the request error."""
    try:
        await proxy.feedback(lease, feedback)
    except Exception as exc:
        logger.debug(
            "proxy feedback failed: context={} kind={} status={} error={}",
            context or "-",
            feedback.kind,
            feedback.status_code,
            exc,
        )


__all__ = ["upstream_feedback", "safe_proxy_feedback"]
