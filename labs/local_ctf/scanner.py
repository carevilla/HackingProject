from __future__ import annotations

import re
import sys
from urllib.parse import urljoin, urlparse
import urllib.error
import urllib.request


PORTS = [8001, 8002, 8003, 8004]
BASE_HOST = "127.0.0.1"
IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp")


def main() -> int:
    show_links = "--links" in sys.argv
    show_images = "--images" in sys.argv

    print("Scanning localhost lab hosts...")
    for port in PORTS:
        url = f"http://{BASE_HOST}:{port}/"
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                html = response.read().decode("utf-8", errors="replace")
                server = response.headers.get("Server", "unknown")
                print(f"[OPEN] {url}  server={server}")
                if show_links:
                    for link in extract_links(html, url):
                        print(f"  -> {link}")
                if show_images:
                    for image_url in discover_images(url):
                        print(f"  [IMAGE] {image_url}")
        except urllib.error.URLError as exc:
            print(f"[CLOSED] {url}  reason={exc.reason}")

    return 0


def extract_links(html: str, base_url: str) -> list[str]:
    matches = re.findall(r'href="([^"]+)"', html, flags=re.IGNORECASE)
    return [urljoin(base_url, match) for match in matches if not match.startswith("?")]


def discover_images(base_url: str) -> list[str]:
    visited: set[str] = set()
    pending = [base_url]
    images: list[str] = []

    while pending:
        url = pending.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                content_type = response.headers.get("Content-Type", "")
                if "text/html" not in content_type:
                    if url.lower().endswith(IMAGE_EXTENSIONS):
                        images.append(url)
                    continue
                html = response.read().decode("utf-8", errors="replace")
        except urllib.error.URLError:
            continue

        for link in extract_links(html, url):
            if not _same_host(base_url, link):
                continue
            if link.lower().endswith(IMAGE_EXTENSIONS):
                images.append(link)
            elif link.endswith("/"):
                pending.append(link)

    return sorted(set(images))


def _same_host(base_url: str, other_url: str) -> bool:
    return urlparse(base_url).netloc == urlparse(other_url).netloc


if __name__ == "__main__":
    raise SystemExit(main())
