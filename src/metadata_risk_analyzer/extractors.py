from __future__ import annotations

from pathlib import Path
from typing import Any

from PIL import ExifTags, Image


GPS_IFD_TAG = 0x8825
EXIF_IFD_TAG = 0x8769


def extract_image_metadata(image_path: str | Path) -> dict[str, Any]:
    path = Path(image_path)
    with Image.open(path) as image:
        metadata: dict[str, Any] = {
            "file_name": path.name,
            "file_path": str(path.resolve()),
            "file_size_bytes": path.stat().st_size,
            "image_format": image.format,
            "width": image.width,
            "height": image.height,
        }

        exif = image.getexif()
        if not exif:
            return metadata

        for tag_id, value in exif.items():
            tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
            metadata[tag_name] = _make_json_safe(value)

        # The Exif sub-IFD holds DateTimeOriginal, DateTimeDigitized, lens info,
        # serial numbers, and similar fields the top-level loop above misses.
        exif_sub = exif.get_ifd(EXIF_IFD_TAG) if EXIF_IFD_TAG in exif else {}
        for tag_id, value in exif_sub.items():
            tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
            metadata.setdefault(tag_name, _make_json_safe(value))

        gps_info = exif.get_ifd(GPS_IFD_TAG) if GPS_IFD_TAG in exif else {}
        if gps_info:
            gps_named = {
                ExifTags.GPSTAGS.get(tag_id, str(tag_id)): value
                for tag_id, value in gps_info.items()
            }
            metadata["GPSInfo"] = _make_json_safe(gps_named)
            coordinates = _extract_coordinates(gps_named)
            if coordinates:
                metadata["gps_latitude"] = coordinates["latitude"]
                metadata["gps_longitude"] = coordinates["longitude"]

        return metadata


def _make_json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, tuple):
        return [_make_json_safe(item) for item in value]
    if isinstance(value, list):
        return [_make_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _make_json_safe(item) for key, item in value.items()}
    return value


def _extract_coordinates(gps_info: dict[str, Any]) -> dict[str, float] | None:
    latitude = _gps_to_decimal(
        gps_info.get("GPSLatitude"),
        gps_info.get("GPSLatitudeRef"),
    )
    longitude = _gps_to_decimal(
        gps_info.get("GPSLongitude"),
        gps_info.get("GPSLongitudeRef"),
    )
    if latitude is None or longitude is None:
        return None
    return {"latitude": latitude, "longitude": longitude}


def _gps_to_decimal(values: Any, reference: Any) -> float | None:
    if not values or not reference or len(values) != 3:
        return None

    degrees = _ratio_to_float(values[0])
    minutes = _ratio_to_float(values[1])
    seconds = _ratio_to_float(values[2])
    decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)

    if str(reference).upper() in {"S", "W"}:
        decimal *= -1
    return round(decimal, 6)


def _ratio_to_float(value: Any) -> float:
    if hasattr(value, "numerator") and hasattr(value, "denominator"):
        return float(value.numerator) / float(value.denominator)
    if isinstance(value, tuple) and len(value) == 2:
        numerator, denominator = value
        return float(numerator) / float(denominator)
    return float(value)
