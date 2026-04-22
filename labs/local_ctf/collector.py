from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import urlparse
import urllib.request

from scanner import discover_images


TARGETS = {
    "alpha": "http://127.0.0.1:8001/",
    "beta": "http://127.0.0.1:8002/",
    "gamma": "http://127.0.0.1:8003/",
    "archive": "http://127.0.0.1:8004/",
}


def main() -> int:
    output_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("labs/local_ctf/loot")
    output_dir.mkdir(parents=True, exist_ok=True)

    for host, base_url in TARGETS.items():
        image_urls = discover_images(base_url)
        if not image_urls:
            print(f"No images discovered for {host} at {base_url}")
            continue

        for image_url in image_urls:
            filename = Path(urlparse(image_url).path).name
            destination = output_dir / f"{host}-{filename}"
            try:
                urllib.request.urlretrieve(image_url, destination)
                print(f"Fetched {image_url} -> {destination}")
            except Exception as exc:  # noqa: BLE001
                print(f"Failed {image_url}: {exc}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
