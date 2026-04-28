from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


# OpenStreetMap Nominatim: free, no API key. Public usage policy requires a
# meaningful User-Agent identifying the app and a maximum of ~1 request per
# second. We add a process-wide rate limiter and an in-memory cache keyed by
# coordinates rounded to ~100m so a folder of nearby photos hits the cache
# instead of spamming OSM.
NOMINATIM_URL = "https://nominatim.openstreetmap.org/reverse"
USER_AGENT = "metadata-risk-analyzer/0.1 (school project; contact: instructor)"

_MIN_INTERVAL_SEC = 1.05
_TIMEOUT_SEC = 4.0
_CACHE_PRECISION = 3   # ~111m at the equator
_CACHE_MAX = 2000      # cap entries to avoid unbounded growth

_cache: dict[tuple[float, float], dict[str, Any] | None] = {}
_cache_lock = threading.Lock()
_request_lock = threading.Lock()
_last_request_time = 0.0


def reverse_geocode(lat: float, lon: float) -> dict[str, Any] | None:
    """Return a small dict with display address fields, or None on failure.

    Result shape:
      {
        "display_name": "1600 Pennsylvania Ave NW, Washington, DC, USA",
        "city": "Washington", "state": "District of Columbia", "country": "USA",
        "country_code": "us", "postcode": "20500",
      }

    Failures (network, rate limit, no result) return None and are cached as
    None so we don't keep retrying the same coordinate forever.
    """
    if lat is None or lon is None:
        return None
    try:
        key = (round(float(lat), _CACHE_PRECISION), round(float(lon), _CACHE_PRECISION))
    except (TypeError, ValueError):
        return None

    with _cache_lock:
        if key in _cache:
            return _cache[key]
        if len(_cache) >= _CACHE_MAX:
            _cache.clear()

    result = _fetch(key[0], key[1])

    with _cache_lock:
        _cache[key] = result
    return result


def _fetch(lat: float, lon: float) -> dict[str, Any] | None:
    global _last_request_time

    # Rate limit: at most one request per ~1 second across all threads
    with _request_lock:
        elapsed = time.monotonic() - _last_request_time
        if elapsed < _MIN_INTERVAL_SEC:
            time.sleep(_MIN_INTERVAL_SEC - elapsed)
        _last_request_time = time.monotonic()

    qs = urllib.parse.urlencode({
        "lat": f"{lat:.5f}",
        "lon": f"{lon:.5f}",
        "format": "jsonv2",
        "zoom": "18",
        "addressdetails": "1",
    })
    req = urllib.request.Request(
        f"{NOMINATIM_URL}?{qs}",
        headers={"User-Agent": USER_AGENT, "Accept-Language": "en"},
    )

    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_SEC) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
        return None

    if not isinstance(payload, dict) or "display_name" not in payload:
        return None

    addr = payload.get("address", {}) or {}
    return {
        "display_name": payload.get("display_name"),
        "city": addr.get("city") or addr.get("town") or addr.get("village") or addr.get("municipality"),
        "state": addr.get("state") or addr.get("region"),
        "country": addr.get("country"),
        "country_code": (addr.get("country_code") or "").lower() or None,
        "postcode": addr.get("postcode"),
    }


def reverse_geocode_many(points: list[tuple[float, float]]) -> dict[tuple[float, float], dict[str, Any] | None]:
    """Lookup multiple coordinates, returning a {point: result} mapping.

    Sequential under the rate limiter (Nominatim's policy forbids parallel
    requests from a single client). Cache hits return immediately so repeated
    coordinates across a batch are essentially free.
    """
    out: dict[tuple[float, float], dict[str, Any] | None] = {}
    for lat, lon in points:
        out[(lat, lon)] = reverse_geocode(lat, lon)
    return out


def clear_cache() -> None:
    """For tests."""
    with _cache_lock:
        _cache.clear()
