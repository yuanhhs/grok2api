"""Admin logs API — read daily log files from the logs/ directory."""

from __future__ import annotations

import re
from pathlib import Path

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from app.platform.paths import log_dir

router = APIRouter()
_TAG = "Admin - Logs"

_LEVEL_RE = re.compile(r"\b(DEBUG|INFO|SUCCESS|WARNING|ERROR|CRITICAL)\b")

# loguru text format:
# 2024-01-02 15:04:05.123 | INFO     | module:func:42 - message
_LINE_RE = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)"
    r"\s*\|\s*(?P<level>[A-Z]+)\s*\|\s*"
    r"(?P<location>[^\s|]+)"
    r"\s*-\s*(?P<message>.+)$"
)


def _list_log_files() -> list[Path]:
    d = log_dir()
    if not d.exists():
        return []
    return sorted(d.glob("app_*.log"), reverse=True)


def _parse_line(raw: str) -> dict | None:
    m = _LINE_RE.match(raw.rstrip())
    if not m:
        return None
    return {
        "time": m.group("time"),
        "level": m.group("level"),
        "location": m.group("location"),
        "message": m.group("message"),
    }


@router.get("/logs/files", tags=[_TAG])
async def list_log_files():
    """Return available log file names (newest first)."""
    files = _list_log_files()
    return {"files": [f.name for f in files]}


@router.get("/logs", tags=[_TAG])
async def get_logs(
    file: str | None = Query(None, description="Log file name, e.g. app_2024-01-02.log"),
    level: str | None = Query(None, description="Filter by level: DEBUG/INFO/WARNING/ERROR"),
    search: str | None = Query(None, description="Case-insensitive keyword filter"),
    page: int = Query(1, ge=1),
    page_size: int = Query(200, ge=1, le=2000),
):
    """Return paginated, filtered log lines."""
    files = _list_log_files()
    if not files:
        return {"lines": [], "total": 0, "page": page, "pages": 0, "file": None, "files": []}

    if file:
        target = log_dir() / file
        if not target.exists() or not target.is_file():
            return JSONResponse({"detail": "File not found"}, status_code=404)
    else:
        target = files[0]

    level_filter = level.upper() if level else None
    search_lower = search.lower() if search else None

    lines: list[dict] = []
    try:
        raw_lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        raw_lines = []

    for raw in reversed(raw_lines):
        parsed = _parse_line(raw)
        if parsed is None:
            continue
        if level_filter and parsed["level"] != level_filter:
            continue
        if search_lower and search_lower not in parsed["message"].lower() and search_lower not in parsed["location"].lower():
            continue
        lines.append(parsed)

    total = len(lines)
    pages = max(1, -(-total // page_size))
    start = (page - 1) * page_size
    page_lines = lines[start: start + page_size]

    return {
        "lines": page_lines,
        "total": total,
        "page": page,
        "pages": pages,
        "file": target.name,
        "files": [f.name for f in files],
    }
