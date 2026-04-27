from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DeviceFingerprint:
    manufacturer: str | None = None
    model: str | None = None
    device_class: str = "unknown"
    os_software: str | None = None
    lens: str | None = None
    serial_numbers: dict[str, str] = field(default_factory=dict)
    host_computer: str | None = None
    unique_id: str | None = None
    confidence: str = "low"
    notes: list[str] = field(default_factory=list)

    @property
    def display_label(self) -> str:
        if self.manufacturer and self.model:
            make_first = self.manufacturer.split()[0].lower()
            model_first = self.model.split()[0].lower()
            if make_first == model_first or self.model.lower().startswith(self.manufacturer.lower()):
                return self.model
            return f"{self.manufacturer} {self.model}"
        return self.model or self.manufacturer or "Unknown device"

    @property
    def has_signal(self) -> bool:
        return bool(
            self.manufacturer
            or self.model
            or self.os_software
            or self.lens
            or self.serial_numbers
            or self.host_computer
            or self.unique_id
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "manufacturer": self.manufacturer,
            "model": self.model,
            "device_class": self.device_class,
            "os_software": self.os_software,
            "lens": self.lens,
            "serial_numbers": dict(self.serial_numbers),
            "host_computer": self.host_computer,
            "unique_id": self.unique_id,
            "confidence": self.confidence,
            "display_label": self.display_label,
            "notes": list(self.notes),
        }


_DEVICE_CLASS_LABELS = {
    "phone":       "Smartphone",
    "tablet":      "Tablet",
    "dslr":        "DSLR",
    "mirrorless":  "Mirrorless camera",
    "compact":     "Compact camera",
    "action":      "Action camera",
    "drone":       "Drone / aerial camera",
    "scanner":     "Scanner",
    "screenshot":  "Screen capture",
    "unknown":     "Unknown class",
}


def device_class_label(device_class: str) -> str:
    return _DEVICE_CLASS_LABELS.get(device_class, device_class.title())


def build_fingerprint(metadata: dict[str, Any]) -> DeviceFingerprint:
    fp = DeviceFingerprint()

    make = _clean(metadata.get("Make"))
    model = _clean(metadata.get("Model"))
    fp.manufacturer = make
    fp.model = model

    software = _clean(metadata.get("Software"))
    if software:
        fp.os_software = software

    lens_model = _clean(metadata.get("LensModel"))
    lens_make = _clean(metadata.get("LensMake"))
    if lens_model and lens_make and not lens_model.lower().startswith(lens_make.lower()):
        fp.lens = f"{lens_make} {lens_model}"
    else:
        fp.lens = lens_model or lens_make

    for key in ("BodySerialNumber", "CameraSerialNumber", "LensSerialNumber"):
        value = _clean(metadata.get(key))
        if value:
            fp.serial_numbers[key] = value

    host = _clean(metadata.get("HostComputer"))
    if host:
        fp.host_computer = host

    unique = _clean(metadata.get("ImageUniqueID")) or _clean(metadata.get("UniqueImageID"))
    if unique:
        fp.unique_id = unique

    fp.device_class, classify_note = _classify_device(make, model)
    if classify_note:
        fp.notes.append(classify_note)

    if make and model:
        fp.notes.append(f"EXIF Make='{make}' + Model='{model}' identify the capture device directly.")
    elif model:
        fp.notes.append(f"EXIF Model='{model}' identifies the device, but Make is missing.")
    elif make:
        fp.notes.append(f"EXIF Make='{make}' identifies the manufacturer; specific model is unknown.")

    if software:
        fp.notes.append(f"Software/firmware tag '{software}' may pin OS or app version.")

    if fp.serial_numbers:
        fp.notes.append(
            "Serial numbers are unique per device — strongest possible link between this image and a physical unit."
        )

    if host:
        fp.notes.append(f"HostComputer='{host}' often reveals the user's machine name (e.g. macOS).")

    fp.confidence = _score_confidence(fp)

    return fp


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().strip("\x00")
    return text or None


def _score_confidence(fp: DeviceFingerprint) -> str:
    score = 0
    if fp.manufacturer:    score += 1
    if fp.model:           score += 2
    if fp.os_software:     score += 1
    if fp.lens:            score += 1
    if fp.serial_numbers:  score += 2
    if fp.host_computer:   score += 1
    if fp.unique_id:       score += 1

    if score >= 5:
        return "high"
    if score >= 2:
        return "medium"
    if score >= 1:
        return "low"
    return "none"


def _classify_device(make: str | None, model: str | None) -> tuple[str, str | None]:
    m = (make or "").lower()
    md = (model or "").strip()
    md_l = md.lower()

    if md_l.startswith("iphone") or ("apple" in m and md_l.startswith("iphone")):
        return "phone", "Apple iPhone family — typical consumer smartphone."
    if "ipad" in md_l:
        return "tablet", "Apple iPad."
    if "samsung" in m and ("sm-" in md_l or "galaxy" in md_l):
        return "phone", "Samsung Galaxy series smartphone."
    if "google" in m and "pixel" in md_l:
        return "phone", "Google Pixel smartphone."
    if any(brand in m for brand in ("huawei", "xiaomi", "oneplus", "oppo", "vivo", "realme", "motorola", "lg electronics", "asus")):
        return "phone", f"{make} smartphone."

    if "dji" in m or md_l.startswith("dji "):
        return "drone", "DJI drone or stabilized camera."

    if "gopro" in m or md_l.startswith("hero"):
        return "action", "GoPro action camera."

    if "canon" in m:
        if md_l.startswith("canon eos r") or md_l.startswith("eos r"):
            return "mirrorless", "Canon EOS R-series mirrorless camera."
        if md_l.startswith("canon eos m") or md_l.startswith("eos m"):
            return "mirrorless", "Canon EOS M-series mirrorless camera."
        if "eos" in md_l:
            return "dslr", "Canon EOS DSLR."
        if "powershot" in md_l:
            return "compact", "Canon PowerShot compact camera."
        return "compact", "Canon camera (specific class not inferred)."

    if "nikon" in m:
        if md_l.startswith("nikon z") or md_l.startswith("z "):
            return "mirrorless", "Nikon Z-series mirrorless camera."
        if md_l.startswith("nikon d") or (md_l.startswith("d") and md_l[1:2].isdigit()):
            return "dslr", "Nikon DSLR."
        if "coolpix" in md_l:
            return "compact", "Nikon Coolpix compact camera."
        return "compact", "Nikon camera (specific class not inferred)."

    if "sony" in m:
        if "ilce" in md_l or "alpha" in md_l or md_l.startswith(("a7", "a6", "a1", "a9")):
            return "mirrorless", "Sony Alpha mirrorless camera."
        if "rx" in md_l or md_l.startswith("dsc"):
            return "compact", "Sony Cyber-shot compact camera."

    if "fujifilm" in m or m == "fuji":
        return "mirrorless", "Fujifilm camera (likely X-series mirrorless)."

    if "olympus" in m or m.startswith("om "):
        return "mirrorless", "Olympus / OM System Micro Four Thirds."

    if "panasonic" in m:
        if "lumix" in md_l or md_l.startswith(("dmc-", "dc-")):
            return "mirrorless", "Panasonic Lumix camera."

    if "leica" in m:
        return "mirrorless", "Leica camera."

    if "screenshot" in md_l or "screencap" in md_l:
        return "screenshot", "Capture appears to be a screenshot, not a physical camera."

    if "scanner" in md_l or "scan" in m:
        return "scanner", "Document or photo scanner."

    return "unknown", None
