from __future__ import annotations

import base64
import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from PIL import Image, ImageStat

try:
    import piexif
    PIEXIF_AVAILABLE = True
except ImportError:
    piexif = None
    PIEXIF_AVAILABLE = False


# Aspect ratio difference up to this fraction is considered "matching"
ASPECT_TOLERANCE = 0.05

# Mean-RGB delta thresholds for the verdict (Euclidean distance, max ~441)
DELTA_CONSISTENT = 25.0
DELTA_MINOR = 60.0


@dataclass
class ThumbnailReport:
    has_thumbnail: bool = False
    thumb_b64: str | None = None
    main_b64: str | None = None
    thumb_dimensions: tuple[int, int] | None = None
    main_dimensions: tuple[int, int] | None = None
    thumb_size_bytes: int = 0
    mean_color_delta: float | None = None
    aspect_match: bool | None = None
    verdict: str = "no_thumbnail"
    verdict_label: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "has_thumbnail": self.has_thumbnail,
            "thumb_b64": self.thumb_b64,
            "main_b64": self.main_b64,
            "thumb_dimensions": list(self.thumb_dimensions) if self.thumb_dimensions else None,
            "main_dimensions": list(self.main_dimensions) if self.main_dimensions else None,
            "thumb_size_bytes": self.thumb_size_bytes,
            "mean_color_delta": round(self.mean_color_delta, 1) if self.mean_color_delta is not None else None,
            "aspect_match": self.aspect_match,
            "verdict": self.verdict,
            "verdict_label": self.verdict_label,
        }


def analyze_thumbnail(image_path) -> ThumbnailReport:
    """Pull the EXIF-embedded JPEG thumbnail (if any) and compare to the main image.

    Returns a ThumbnailReport with a verdict in:
      - no_thumbnail      -- nothing embedded (common for screenshots, sanitized,
                             non-camera images)
      - consistent        -- thumbnail looks like a faithful preview of the main
      - minor_difference  -- small color/exposure difference; usually compression
      - suspicious        -- significantly different mean color; main may have
                             been edited after the thumbnail was generated
      - aspect_mismatch   -- thumbnail aspect ratio doesn't match the main image
                             (strong manipulation indicator)
    """
    rep = ThumbnailReport()
    image_path = Path(image_path)

    if not PIEXIF_AVAILABLE:
        rep.verdict_label = "piexif not installed — embedded-thumbnail check unavailable."
        return rep

    try:
        exif_dict = piexif.load(str(image_path))
    except Exception:
        rep.verdict_label = "Could not parse EXIF — thumbnail check skipped."
        return rep

    thumb_bytes = exif_dict.get("thumbnail")
    if not thumb_bytes:
        rep.verdict = "no_thumbnail"
        rep.verdict_label = (
            "No embedded thumbnail. Camera photos almost always include one — "
            "absence may indicate a screenshot, a sanitized image, or a re-encode."
        )
        return rep

    rep.has_thumbnail = True
    rep.thumb_size_bytes = len(thumb_bytes)
    rep.thumb_b64 = "data:image/jpeg;base64," + base64.b64encode(thumb_bytes).decode("ascii")

    try:
        thumb_img = Image.open(io.BytesIO(thumb_bytes)).convert("RGB")
        rep.thumb_dimensions = thumb_img.size
    except Exception:
        rep.verdict = "suspicious"
        rep.verdict_label = "Embedded thumbnail bytes are present but unreadable — possible tampering."
        return rep

    try:
        with Image.open(image_path) as main_img:
            rep.main_dimensions = main_img.size
            main_rgb = main_img.convert("RGB")
            main_resized = main_rgb.resize(thumb_img.size, Image.Resampling.LANCZOS)

            buf = io.BytesIO()
            main_resized.save(buf, format="JPEG", quality=82)
            rep.main_b64 = "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode("ascii")

            rep.mean_color_delta = _mean_color_delta(thumb_img, main_resized)

            thumb_aspect = thumb_img.size[0] / thumb_img.size[1]
            main_aspect = rep.main_dimensions[0] / rep.main_dimensions[1]
            rep.aspect_match = abs(thumb_aspect - main_aspect) / max(thumb_aspect, main_aspect) < ASPECT_TOLERANCE
    except Exception as exc:
        rep.verdict_label = f"Could not compare to main image: {exc}"
        return rep

    if not rep.aspect_match:
        rep.verdict = "aspect_mismatch"
        rep.verdict_label = (
            "Thumbnail aspect ratio doesn't match the main image — "
            "strong indicator that the image was cropped or replaced after the thumbnail was generated."
        )
    elif rep.mean_color_delta is None:
        rep.verdict_label = "Thumbnail extracted but couldn't compare to main."
    elif rep.mean_color_delta < DELTA_CONSISTENT:
        rep.verdict = "consistent"
        rep.verdict_label = "Thumbnail closely matches the main image — likely untouched since capture."
    elif rep.mean_color_delta < DELTA_MINOR:
        rep.verdict = "minor_difference"
        rep.verdict_label = (
            "Thumbnail differs slightly from the main — usually normal compression or "
            "in-camera processing, but worth noting if the image is otherwise suspicious."
        )
    else:
        rep.verdict = "suspicious"
        rep.verdict_label = (
            "Thumbnail differs significantly from the main image. The main may have been "
            "edited after the thumbnail was generated, leaving a stale preview behind — "
            "this is a classic forensic gotcha."
        )

    return rep


def _mean_color_delta(img1: Image.Image, img2: Image.Image) -> float:
    """Euclidean distance between the mean RGB of two same-size RGB images."""
    m1 = ImageStat.Stat(img1).mean[:3]
    m2 = ImageStat.Stat(img2).mean[:3]
    return ((m1[0] - m2[0]) ** 2 + (m1[1] - m2[1]) ** 2 + (m1[2] - m2[2]) ** 2) ** 0.5


# ── Tampering / authenticity indicators ──────────────────────────────────────

# Substrings that reveal a known photo editor in the Software EXIF tag. All
# matched case-insensitively. Camera firmware ("iOS 18.3", "1.8.0") won't trip
# any of these, so a hit is a fairly strong "this was edited" signal.
_EDITOR_SIGNATURES = (
    "adobe", "photoshop", "lightroom", "gimp", "snapseed", "vsco",
    "affinity", "pixelmator", "luminar", "darktable", "rawtherapee",
    "capture one", "skylum", "topaz", "facetune", "picsart", "fotor",
)

_TIMESTAMP_FIELDS = ("DateTimeOriginal", "DateTimeDigitized", "DateTime")

_SEVERITY_WEIGHTS = {"info": 5, "low": 10, "medium": 25, "high": 40}


@dataclass
class TamperingIndicator:
    name: str
    title: str
    severity: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "title": self.title, "severity": self.severity, "detail": self.detail}


@dataclass
class TamperingReport:
    indicators: list[TamperingIndicator] = field(default_factory=list)
    score: int = 0
    verdict: str = "clean"
    verdict_label: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicators": [i.to_dict() for i in self.indicators],
            "score": self.score,
            "verdict": self.verdict,
            "verdict_label": self.verdict_label,
        }


def analyze_tampering(
    metadata: dict[str, Any],
    thumbnail_report: ThumbnailReport | None = None,
) -> TamperingReport:
    """Inspect EXIF + thumbnail evidence for signs the image has been edited.

    Returns a TamperingReport with weighted indicators and an overall verdict
    in {clean, lightly_touched, likely_edited, heavily_edited}.
    """
    indicators: list[TamperingIndicator] = []

    # 1. Software field reveals a known editor
    software_raw = metadata.get("Software")
    if software_raw:
        s = str(software_raw).lower()
        editor = next((e for e in _EDITOR_SIGNATURES if e in s), None)
        if editor:
            indicators.append(TamperingIndicator(
                name="editor_software",
                title="Editor signature in Software tag",
                severity="high",
                detail=(
                    f"Software field reads '{software_raw}' — a known photo editor. "
                    "Camera firmware would normally appear here instead."
                ),
            ))

    # 2. EXIF timestamps disagree
    timestamps = {f: str(metadata[f]).strip() for f in _TIMESTAMP_FIELDS if metadata.get(f)}
    distinct_values = {v for v in timestamps.values() if v}
    if len(timestamps) >= 2 and len(distinct_values) > 1:
        listing = ", ".join(f"{k}='{v}'" for k, v in timestamps.items())
        indicators.append(TamperingIndicator(
            name="inconsistent_timestamps",
            title="EXIF timestamps don't agree",
            severity="medium",
            detail=(
                f"{listing}. Cameras normally write all three timestamps "
                "identically at capture; later editing usually only updates DateTime."
            ),
        ))

    # 3. EXIF-recorded dimensions differ from actual file dimensions
    exif_w = _to_int(metadata.get("ExifImageWidth")) or _to_int(metadata.get("PixelXDimension"))
    exif_h = _to_int(metadata.get("ExifImageHeight")) or _to_int(metadata.get("PixelYDimension"))
    actual_w = _to_int(metadata.get("width"))
    actual_h = _to_int(metadata.get("height"))
    if exif_w and exif_h and actual_w and actual_h and (exif_w, exif_h) != (actual_w, actual_h):
        indicators.append(TamperingIndicator(
            name="dimension_mismatch",
            title="EXIF dimensions don't match the file",
            severity="medium",
            detail=(
                f"EXIF claims {exif_w}×{exif_h} but the file is actually {actual_w}×{actual_h}. "
                "The image was likely cropped or resized after capture."
            ),
        ))

    # 4. Thumbnail-derived signals (delegated to the thumbnail check)
    if thumbnail_report:
        if thumbnail_report.verdict == "aspect_mismatch":
            indicators.append(TamperingIndicator(
                name="thumbnail_aspect_mismatch",
                title="Thumbnail aspect ratio mismatch",
                severity="high",
                detail=(
                    "Embedded thumbnail's aspect ratio differs from the main image — "
                    "a strong indicator that the main was cropped or replaced."
                ),
            ))
        elif thumbnail_report.verdict == "suspicious":
            indicators.append(TamperingIndicator(
                name="thumbnail_stale",
                title="Thumbnail differs from main image",
                severity="medium",
                detail=(
                    f"Mean color delta {thumbnail_report.mean_color_delta} between "
                    "the thumbnail and the main suggests the main was edited after "
                    "the thumbnail was generated (a classic forensic gotcha)."
                ),
            ))
        elif thumbnail_report.verdict == "no_thumbnail" and (metadata.get("Make") or metadata.get("Model")):
            indicators.append(TamperingIndicator(
                name="thumbnail_missing",
                title="Camera-tagged image without thumbnail",
                severity="medium",
                detail=(
                    "Image identifies a camera (Make/Model present) but has no "
                    "embedded thumbnail. Cameras almost always include one; "
                    "absence usually means the image has been re-encoded or sanitized."
                ),
            ))

    # 5. Camera identified but MakerNote blob is missing (re-encode hint)
    has_camera = bool(metadata.get("Make") or metadata.get("Model"))
    has_makernote = bool(metadata.get("MakerNote"))
    if has_camera and not has_makernote:
        indicators.append(TamperingIndicator(
            name="missing_makernote",
            title="Camera tagged but MakerNote stripped",
            severity="info",
            detail=(
                "Make/Model are present but the vendor-specific MakerNote blob is "
                "absent. Cameras embed it on capture; its absence usually means a "
                "re-encode, sanitization step, or export from a non-camera tool."
            ),
        ))

    score = min(100, sum(_SEVERITY_WEIGHTS[i.severity] for i in indicators))

    if score == 0:
        verdict, label = "clean", "No tampering signals detected. Metadata looks consistent with a fresh, unedited capture."
    elif score < 25:
        verdict, label = "lightly_touched", "A minor tampering signal was detected — could be normal in-camera processing or sanitization."
    elif score < 50:
        verdict, label = "likely_edited", "Multiple tampering signals detected. The image has likely been edited or re-processed after capture."
    else:
        verdict, label = "heavily_edited", "Strong tampering signals detected. The image has almost certainly been edited — treat its metadata with skepticism."

    return TamperingReport(indicators=indicators, score=score, verdict=verdict, verdict_label=label)


def _to_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
