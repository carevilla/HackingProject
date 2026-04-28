from __future__ import annotations

import io
from typing import Any

try:
    import piexif
    PIEXIF_AVAILABLE = True
except ImportError:
    piexif = None
    PIEXIF_AVAILABLE = False


SUPPORTED_EXTENSIONS = {".jpg", ".jpeg"}


class SpoofError(Exception):
    """Raised when an EXIF spoof or sanitize operation cannot be performed."""


def sanitize(image_bytes: bytes) -> bytes:
    """Return the JPEG with all EXIF removed."""
    _require_piexif()
    _require_jpeg(image_bytes)
    out = io.BytesIO()
    piexif.remove(image_bytes, out)
    return out.getvalue()


def spoof(image_bytes: bytes, overrides: dict[str, Any]) -> bytes:
    """Return the JPEG with selected EXIF fields overridden.

    `overrides` keys (all optional):
      make, model, software             -- str, sets the corresponding 0th IFD tag
      datetime_original                  -- ISO-ish datetime string ("YYYY-MM-DDTHH:MM"
                                            or "YYYY-MM-DD HH:MM:SS"); writes Original,
                                            Digitized, and DateTime tags together
      latitude, longitude                -- floats in decimal degrees; writes a fresh
                                            GPS IFD (lat/lon + N/S/E/W refs)
      strip_gps                          -- if truthy, clears the GPS IFD entirely
                                            (ignored when latitude/longitude are set)
      strip_serials                      -- if truthy, removes BodySerialNumber,
                                            CameraOwnerName, LensSerialNumber
    """
    _require_piexif()
    _require_jpeg(image_bytes)

    try:
        exif_dict = piexif.load(image_bytes)
    except Exception:
        exif_dict = {"0th": {}, "Exif": {}, "GPS": {}, "1st": {}, "thumbnail": None}

    # Ensure all expected sub-IFDs exist
    for key in ("0th", "Exif", "GPS", "1st"):
        exif_dict.setdefault(key, {})
    exif_dict.setdefault("thumbnail", None)

    _apply_overrides(exif_dict, overrides)

    try:
        exif_bytes = piexif.dump(exif_dict)
    except Exception as exc:
        raise SpoofError(f"Could not encode EXIF: {exc}") from exc

    out = io.BytesIO()
    piexif.insert(exif_bytes, image_bytes, out)
    return out.getvalue()


def _apply_overrides(exif_dict: dict, o: dict[str, Any]) -> None:
    if o.get("make"):
        exif_dict["0th"][piexif.ImageIFD.Make] = str(o["make"]).encode("utf-8")
    if o.get("model"):
        exif_dict["0th"][piexif.ImageIFD.Model] = str(o["model"]).encode("utf-8")
    if o.get("software"):
        exif_dict["0th"][piexif.ImageIFD.Software] = str(o["software"]).encode("utf-8")

    if o.get("datetime_original"):
        ts = _format_exif_datetime(str(o["datetime_original"]))
        exif_dict["Exif"][piexif.ExifIFD.DateTimeOriginal] = ts.encode("ascii")
        exif_dict["Exif"][piexif.ExifIFD.DateTimeDigitized] = ts.encode("ascii")
        exif_dict["0th"][piexif.ImageIFD.DateTime] = ts.encode("ascii")

    lat = o.get("latitude")
    lon = o.get("longitude")
    if lat is not None and lon is not None:
        exif_dict["GPS"] = _build_gps_ifd(float(lat), float(lon))
    elif o.get("strip_gps"):
        exif_dict["GPS"] = {}

    if o.get("strip_serials"):
        for tag in (
            getattr(piexif.ExifIFD, "BodySerialNumber", None),
            getattr(piexif.ExifIFD, "CameraOwnerName", None),
            getattr(piexif.ExifIFD, "LensSerialNumber", None),
        ):
            if tag is not None:
                exif_dict["Exif"].pop(tag, None)


def _format_exif_datetime(raw: str) -> str:
    """Convert a user-supplied datetime to EXIF format `YYYY:MM:DD HH:MM:SS`."""
    s = raw.strip().replace("T", " ")
    if len(s) == 16:
        s += ":00"
    if len(s) >= 10 and s[4] == "-":
        s = s[:4] + ":" + s[5:7] + ":" + s[8:]
    if len(s) != 19:
        raise SpoofError(f"Could not parse timestamp '{raw}' (expected YYYY-MM-DD HH:MM[:SS]).")
    return s


def _build_gps_ifd(lat: float, lon: float) -> dict:
    return {
        piexif.GPSIFD.GPSLatitudeRef: b"N" if lat >= 0 else b"S",
        piexif.GPSIFD.GPSLatitude: _decimal_to_dms_rationals(abs(lat)),
        piexif.GPSIFD.GPSLongitudeRef: b"E" if lon >= 0 else b"W",
        piexif.GPSIFD.GPSLongitude: _decimal_to_dms_rationals(abs(lon)),
        piexif.GPSIFD.GPSVersionID: (2, 0, 0, 0),
    }


def _decimal_to_dms_rationals(decimal: float) -> tuple:
    deg = int(decimal)
    min_decimal = (decimal - deg) * 60
    minutes = int(min_decimal)
    seconds = (min_decimal - minutes) * 60
    return ((deg, 1), (minutes, 1), (int(round(seconds * 10000)), 10000))


def _require_piexif() -> None:
    if not PIEXIF_AVAILABLE:
        raise SpoofError(
            "The 'piexif' package is required for EXIF spoofing. "
            "Install it with: pip install piexif"
        )


def _require_jpeg(image_bytes: bytes) -> None:
    if not image_bytes or image_bytes[:2] != b"\xff\xd8":
        raise SpoofError("Spoofer supports JPEG images only.")
