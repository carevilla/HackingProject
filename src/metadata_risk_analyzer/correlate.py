from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class DeviceGroup:
    key: str
    label: str
    sublabel: str
    device_class: str
    match_strength: str
    match_label: str
    image_indices: list[int] = field(default_factory=list)
    image_paths: list[str] = field(default_factory=list)
    software_versions: set[str] = field(default_factory=set)
    lenses: set[str] = field(default_factory=set)

    @property
    def count(self) -> int:
        return len(self.image_indices)

    def to_dict(self) -> dict[str, Any]:
        images = [
            {"index": i, "path": p}
            for i, p in zip(self.image_indices, self.image_paths)
        ]
        return {
            "key": self.key,
            "label": self.label,
            "sublabel": self.sublabel,
            "device_class": self.device_class,
            "match_strength": self.match_strength,
            "match_label": self.match_label,
            "images": images,
            "software_versions": sorted(self.software_versions),
            "lenses": sorted(self.lenses),
            "count": self.count,
        }


_MATCH_LABEL = {
    "serial":       "Same physical body (serial match)",
    "model":        "Same make + model",
    "manufacturer": "Same manufacturer only",
    "unknown":      "No device signal",
}

_STRENGTH_ORDER = {"serial": 0, "model": 1, "manufacturer": 2, "unknown": 3}


def group_by_device(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group report dicts by inferred device identity.

    Returns an empty list when there is fewer than 2 reports — grouping a single
    image is meaningless. Output is JSON-serializable for direct template use.
    """
    if len(reports) < 2:
        return []

    groups: dict[tuple, DeviceGroup] = {}

    for idx, report in enumerate(reports):
        fp = report.get("device_fingerprint") or {}
        raw_key, strength, sublabel = _device_key(fp)

        if raw_key not in groups:
            groups[raw_key] = DeviceGroup(
                key=_safe_html_id(raw_key),
                label=fp.get("display_label") or "Unknown device",
                sublabel=sublabel,
                device_class=fp.get("device_class") or "unknown",
                match_strength=strength,
                match_label=_MATCH_LABEL[strength],
            )

        g = groups[raw_key]
        g.image_indices.append(idx)
        g.image_paths.append(report.get("image_path") or f"image #{idx}")
        if fp.get("os_software"):
            g.software_versions.add(fp["os_software"])
        if fp.get("lens"):
            g.lenses.add(fp["lens"])

    sorted_groups = sorted(
        groups.values(),
        key=lambda g: (-g.count, _STRENGTH_ORDER[g.match_strength], g.label.lower()),
    )
    return [g.to_dict() for g in sorted_groups]


def _device_key(fp: dict[str, Any]) -> tuple[tuple, str, str]:
    serials = fp.get("serial_numbers") or {}
    body = serials.get("BodySerialNumber") or serials.get("CameraSerialNumber")
    if body:
        return (("serial", "body", str(body)), "serial", f"Body serial: {body}")

    make = (fp.get("manufacturer") or "").strip()
    model = (fp.get("model") or "").strip()

    if make and model:
        return (("model", make.lower(), model.lower()), "model", f"{make} · {model}")
    if model:
        return (("model", "", model.lower()), "model", model)
    if make:
        return (("manufacturer", make.lower()), "manufacturer", make)

    return (("unknown",), "unknown", "Images without device EXIF")


def _safe_html_id(raw_key: tuple) -> str:
    raw = "|".join(str(p) for p in raw_key)
    return "dg-" + hashlib.md5(raw.encode("utf-8")).hexdigest()[:10]


# ── GPS clustering ────────────────────────────────────────────────────────────

EARTH_RADIUS_M = 6_371_000
DEFAULT_CLUSTER_RADIUS_M = 150.0
DEFAULT_HOTSPOT_THRESHOLD = 3

_TIMESTAMP_FIELDS = ("DateTimeOriginal", "DateTime", "DateTimeDigitized")


@dataclass
class LocationCluster:
    key: str
    centroid_lat: float
    centroid_lon: float
    radius_m: float
    is_hotspot: bool
    images: list[dict[str, Any]] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.images)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "centroid_lat": round(self.centroid_lat, 6),
            "centroid_lon": round(self.centroid_lon, 6),
            "radius_m": round(self.radius_m, 1),
            "is_hotspot": self.is_hotspot,
            "count": self.count,
            "images": list(self.images),
        }


def cluster_locations(
    reports: list[dict[str, Any]],
    radius_m: float = DEFAULT_CLUSTER_RADIUS_M,
    hotspot_threshold: int = DEFAULT_HOTSPOT_THRESHOLD,
) -> list[dict[str, Any]]:
    """Greedy single-pass clustering of geotagged images by proximity.

    For each image with GPS, find the nearest existing cluster centroid; if
    within `radius_m` meters, join it (and update the centroid as a running
    mean), otherwise start a new cluster. Clusters with `>= hotspot_threshold`
    images are flagged as hotspots ("frequent location").

    Returns an empty list when fewer than 2 reports are provided — the
    per-report map already covers single-image cases.
    """
    if len(reports) < 2:
        return []

    points = []
    for idx, report in enumerate(reports):
        meta = report.get("metadata") or {}
        lat = meta.get("gps_latitude")
        lon = meta.get("gps_longitude")
        if lat is None or lon is None:
            continue
        timestamp = next((meta.get(f) for f in _TIMESTAMP_FIELDS if meta.get(f)), None)
        fp = report.get("device_fingerprint") or {}
        points.append({
            "index": idx,
            "path": report.get("image_path") or f"image #{idx}",
            "lat": float(lat),
            "lon": float(lon),
            "timestamp": timestamp,
            "device_label": fp.get("display_label"),
        })

    if not points:
        return []

    clusters: list[LocationCluster] = []

    for point in points:
        nearest, nearest_dist = None, float("inf")
        for cluster in clusters:
            dist = _haversine_m(point["lat"], point["lon"], cluster.centroid_lat, cluster.centroid_lon)
            if dist < nearest_dist:
                nearest, nearest_dist = cluster, dist

        if nearest is not None and nearest_dist <= radius_m:
            n = nearest.count
            nearest.centroid_lat = (nearest.centroid_lat * n + point["lat"]) / (n + 1)
            nearest.centroid_lon = (nearest.centroid_lon * n + point["lon"]) / (n + 1)
            nearest.images.append(point)
            nearest.radius_m = max(
                _haversine_m(p["lat"], p["lon"], nearest.centroid_lat, nearest.centroid_lon)
                for p in nearest.images
            )
        else:
            clusters.append(LocationCluster(
                key=_safe_html_id(("loc", round(point["lat"], 5), round(point["lon"], 5), point["index"])),
                centroid_lat=point["lat"],
                centroid_lon=point["lon"],
                radius_m=0.0,
                is_hotspot=False,
                images=[point],
            ))

    for cluster in clusters:
        cluster.is_hotspot = cluster.count >= hotspot_threshold

    clusters.sort(key=lambda c: (-c.count, c.centroid_lat, c.centroid_lon))
    return [c.to_dict() for c in clusters]


def _haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * EARTH_RADIUS_M * math.asin(math.sqrt(a))


# ── Timeline reconstruction ───────────────────────────────────────────────────

_EXIF_TS_FIELDS = ("DateTimeOriginal", "DateTime", "DateTimeDigitized")
_EXIF_TS_FORMATS = ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y:%m:%dT%H:%M:%S")
_WEEKDAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def build_timeline(reports: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Sort timestamped images chronologically and compute distribution stats.

    Returns None when fewer than 2 reports carry a parseable EXIF timestamp.
    The output dict is JSON-serializable for direct embedding in the template.
    """
    if len(reports) < 2:
        return None

    events: list[dict[str, Any]] = []
    for idx, report in enumerate(reports):
        meta = report.get("metadata") or {}
        raw = next((meta.get(f) for f in _EXIF_TS_FIELDS if meta.get(f)), None)
        dt = _parse_exif_dt(raw)
        if dt is None:
            continue
        fp = report.get("device_fingerprint") or {}
        events.append({
            "index": idx,
            "path": report.get("image_path") or f"image #{idx}",
            "iso": dt.isoformat(),
            "display": dt.strftime("%Y-%m-%d %H:%M"),
            "hour": dt.hour,
            "weekday": dt.weekday(),
            "device_label": fp.get("display_label"),
        })

    if len(events) < 2:
        return None

    events.sort(key=lambda e: e["iso"])

    earliest_dt = datetime.fromisoformat(events[0]["iso"])
    latest_dt = datetime.fromisoformat(events[-1]["iso"])
    span_seconds = (latest_dt - earliest_dt).total_seconds()

    hour_hist = [0] * 24
    weekday_hist = [0] * 7
    for e in events:
        hour_hist[e["hour"]] += 1
        weekday_hist[e["weekday"]] += 1

    longest_gap = None
    if len(events) >= 2:
        max_seconds, gap_start, gap_end = 0.0, None, None
        for prev, curr in zip(events, events[1:]):
            delta = (datetime.fromisoformat(curr["iso"]) - datetime.fromisoformat(prev["iso"])).total_seconds()
            if delta > max_seconds:
                max_seconds, gap_start, gap_end = delta, prev["iso"], curr["iso"]
        if max_seconds > 0:
            longest_gap = {
                "start": gap_start,
                "end": gap_end,
                "days": round(max_seconds / 86400, 2),
                "human": _humanize_duration(max_seconds),
            }

    peak_hour = max(range(24), key=lambda h: hour_hist[h]) if any(hour_hist) else None
    peak_weekday = max(range(7), key=lambda d: weekday_hist[d]) if any(weekday_hist) else None

    available_years = sorted({datetime.fromisoformat(e["iso"]).year for e in events})
    default_year = available_years[-1] if available_years else None

    return {
        "events": events,
        "earliest": events[0]["iso"],
        "latest": events[-1]["iso"],
        "span_days": round(span_seconds / 86400, 2),
        "span_human": _humanize_duration(span_seconds) if span_seconds > 0 else "less than a minute",
        "hour_histogram": hour_hist,
        "weekday_histogram": weekday_hist,
        "weekday_names": _WEEKDAY_NAMES,
        "peak_hour": peak_hour,
        "peak_hour_count": hour_hist[peak_hour] if peak_hour is not None else 0,
        "peak_weekday": peak_weekday,
        "peak_weekday_name": _WEEKDAY_NAMES[peak_weekday] if peak_weekday is not None else None,
        "peak_weekday_count": weekday_hist[peak_weekday] if peak_weekday is not None else 0,
        "longest_gap": longest_gap,
        "missing_count": len(reports) - len(events),
        "available_years": available_years,
        "default_year": default_year,
    }


def _parse_exif_dt(value: Any) -> datetime | None:
    if not value:
        return None
    s = str(value).strip().rstrip("\x00")
    if not s or s.startswith("0000"):
        return None
    for fmt in _EXIF_TS_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def build_sort_keys(
    reports: list[dict[str, Any]],
    device_groups: list[dict[str, Any]],
    location_clusters: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Per-report data-attribute payloads that drive client-side sorting."""
    keys: list[dict[str, Any]] = [{} for _ in reports]

    for group in device_groups:
        for img in group.get("images", []):
            keys[img["index"]]["device_key"] = group["key"]
            keys[img["index"]]["device_label"] = group["label"]

    for cluster in location_clusters:
        for img in cluster.get("images", []):
            keys[img["index"]]["location_key"] = cluster["key"]
            keys[img["index"]]["location_lat"] = cluster["centroid_lat"]
            keys[img["index"]]["location_lon"] = cluster["centroid_lon"]

    for idx, report in enumerate(reports):
        meta = report.get("metadata") or {}
        raw = next((meta.get(f) for f in _EXIF_TS_FIELDS if meta.get(f)), None)
        dt = _parse_exif_dt(raw)
        if dt is not None:
            keys[idx]["iso_timestamp"] = dt.isoformat()
            keys[idx]["hour"] = dt.hour

        # Fall back to the per-report fingerprint label when the report is the
        # only one of its kind (group_by_device returns [] for <2 reports, so
        # everything would otherwise be unlabelled in the single-upload case).
        if "device_label" not in keys[idx]:
            fp = report.get("device_fingerprint") or {}
            label = fp.get("display_label")
            if label and label != "Unknown device":
                keys[idx]["device_label"] = label

    return keys


def _humanize_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{int(seconds / 60)} min"
    if seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f} hr" if hours < 10 else f"{int(hours)} hr"
    days = seconds / 86400
    if days < 30:
        return f"{days:.1f} days" if days < 10 else f"{int(days)} days"
    if days < 365:
        return f"{days / 30:.1f} months"
    return f"{days / 365:.1f} years"
