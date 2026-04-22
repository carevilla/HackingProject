from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


LAB_ROOT = Path(__file__).resolve().parent
ASSET_ROOT = LAB_ROOT / "host_assets"

HOST_IMAGE_CONFIG = {
    "alpha": {
        "filename": "leaked_alpha.jpg",
        "color": "#A8C9A4",
        "lines": ["alpha", "low-risk workstation"],
        "exif": {
            271: "ScreenshotTool",
            272: "Desktop Capture",
            305: "Snip Utility",
        },
    },
    "beta": {
        "filename": "leaked_beta.jpg",
        "color": "#DDB892",
        "lines": ["beta", "phone image with time clues"],
        "exif": {
            271: "Apple",
            272: "iPhone 15",
            305: "iOS 18.3",
            306: "2026:04:22 07:30:00",
            36867: "2026:04:22 07:28:00",
            36868: "2026:04:22 07:28:00",
        },
    },
    "gamma": {
        "filename": "leaked_gamma.jpg",
        "color": "#C8B6FF",
        "lines": ["gamma", "camera image with tracking clues"],
        "exif": {
            271: "Canon",
            272: "EOS R6",
            305: "Adobe Photoshop 25.0",
            315: "Chris R.",
            33432: "Chris Revilla",
            36867: "2026:04:22 17:11:42",
            42033: "2389001472",
            42036: "RF24-70mm F2.8 L IS USM",
            42016: "IMG-UNIQUE-44719",
        },
    },
    "archive": {
        "filename": "leaked_archive.jpg",
        "color": "#9EC5FE",
        "lines": ["archive", "owner-tagged shared image"],
        "exif": {
            271: "Nikon",
            272: "Z6 II",
            315: "Lab Archivist",
            316: "ARCHIVE-WS01",
            306: "2026:04:19 14:10:00",
        },
    },
}


def main() -> None:
    ASSET_ROOT.mkdir(parents=True, exist_ok=True)
    for host, config in HOST_IMAGE_CONFIG.items():
        host_dir = ASSET_ROOT / host
        host_dir.mkdir(parents=True, exist_ok=True)
        image_path = host_dir / config["filename"]
        _create_image(image_path, config["color"], config["lines"], config["exif"])
        _write_index(host_dir, config["filename"], host)
        print(f"Created {image_path}")


def _create_image(image_path: Path, color: str, lines: list[str], exif_fields: dict[int, str]) -> None:
    image = Image.new("RGB", (1280, 720), color)
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default()

    y = 260
    for line in lines:
        draw.text((70, y), line, fill="black", font=font)
        y += 40

    exif = Image.Exif()
    for tag_id, value in exif_fields.items():
        exif[tag_id] = value

    image.save(image_path, format="JPEG", exif=exif)


def _write_index(host_dir: Path, image_name: str, host: str) -> None:
    index_path = host_dir / "index.html"
    index_path.write_text(
        "\n".join(
            [
                "<!doctype html>",
                "<html lang=\"en\">",
                "<head><meta charset=\"utf-8\"><title>Shared Assets</title></head>",
                "<body>",
                f"<h1>{host} shared assets</h1>",
                f"<p><a href=\"{image_name}\">{image_name}</a></p>",
                "</body>",
                "</html>",
            ]
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
