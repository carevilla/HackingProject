from __future__ import annotations

import sys
import urllib.request
from pathlib import Path


TARGETS = {
    "alpha": ("10.0.0.11", "leaked_alpha.jpg"),
    "beta": ("10.0.0.12", "leaked_beta.jpg"),
    "gamma": ("10.0.0.13", "leaked_gamma.jpg"),
    "archive": ("10.0.0.14", "leaked_archive.jpg"),
}


def main() -> int:
    output_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/loot")
    output_dir.mkdir(parents=True, exist_ok=True)

    for host, (ip, filename) in TARGETS.items():
        url = f"http://{ip}:8000/{filename}"
        destination = output_dir / f"{host}-{filename}"
        try:
            urllib.request.urlretrieve(url, destination)
            print(f"Fetched {url} -> {destination}")
        except Exception as exc:  # noqa: BLE001
            print(f"Failed {url}: {exc}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
