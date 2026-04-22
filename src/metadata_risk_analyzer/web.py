from __future__ import annotations

import tempfile
from pathlib import Path
import re
from urllib.parse import urljoin, urlparse
import urllib.error
import urllib.request

from flask import Flask, render_template, request
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from .analyzer import analyze_image
from .demo_data import DEMO_SCENARIOS, build_demo_report


ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".tiff", ".tif", ".webp"}
LOCAL_LAB_HOSTS = {
    "alpha": "http://127.0.0.1:8001/",
    "beta": "http://127.0.0.1:8002/",
    "gamma": "http://127.0.0.1:8003/",
    "archive": "http://127.0.0.1:8004/",
}
LOCAL_LOOT_DIR = Path("labs/local_ctf/loot")


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

    @app.get("/")
    def index():
        return render_template(
            "index.html",
            reports=None,
            errors=None,
            demo_scenarios=DEMO_SCENARIOS,
            scan_results=None,
        )

    @app.post("/analyze")
    def analyze():
        uploads = request.files.getlist("images")
        reports = []
        errors: list[str] = []

        for upload in uploads:
            if not _is_valid_upload(upload):
                if upload and upload.filename:
                    errors.append(f"{upload.filename}: unsupported file type.")
                continue

            try:
                report = _analyze_upload(upload)
                reports.append(report.to_dict())
            except OSError as exc:
                errors.append(f"{upload.filename}: {exc}")

        if not uploads or all(not upload.filename for upload in uploads):
            errors.append("Choose at least one image to analyze.")

        return render_template(
            "index.html",
            reports=reports,
            errors=errors,
            demo_scenarios=DEMO_SCENARIOS,
            scan_results=None,
        )

    @app.post("/demo")
    def demo():
        scenario_name = request.form.get("scenario", "")
        errors: list[str] = []
        reports = []

        if scenario_name not in DEMO_SCENARIOS:
            errors.append("Unknown demo scenario selected.")
        else:
            reports.append(build_demo_report(scenario_name).to_dict())

        return render_template(
            "index.html",
            reports=reports,
            errors=errors,
            demo_scenarios=DEMO_SCENARIOS,
            scan_results=None,
        )

    @app.post("/lab/scan")
    def lab_scan():
        return render_template(
            "index.html",
            reports=None,
            errors=None,
            demo_scenarios=DEMO_SCENARIOS,
            scan_results=_scan_local_lab(),
        )

    @app.post("/lab/loot")
    def lab_loot():
        reports = []
        errors: list[str] = []

        if not LOCAL_LOOT_DIR.exists():
            errors.append("No local loot folder found yet. Run the collector first.")
        else:
            for path in sorted(LOCAL_LOOT_DIR.iterdir()):
                if not path.is_file() or path.suffix.lower() not in ALLOWED_EXTENSIONS:
                    continue
                try:
                    report = analyze_image(path)
                    report.image_path = path.name
                    report.metadata["file_name"] = path.name
                    report.metadata.pop("file_path", None)
                    reports.append(report.to_dict())
                except OSError as exc:
                    errors.append(f"{path.name}: {exc}")

            if not reports and not errors:
                errors.append("The loot folder exists, but no supported image files were found.")

        return render_template(
            "index.html",
            reports=reports,
            errors=errors,
            demo_scenarios=DEMO_SCENARIOS,
            scan_results=_scan_local_lab(),
        )

    return app


def _is_valid_upload(upload: FileStorage) -> bool:
    if not upload or not upload.filename:
        return False
    extension = Path(upload.filename).suffix.lower()
    return extension in ALLOWED_EXTENSIONS


def _analyze_upload(upload: FileStorage):
    suffix = Path(upload.filename or "").suffix.lower()
    safe_name = secure_filename(upload.filename or "uploaded-image")

    with tempfile.NamedTemporaryFile(prefix="metadata-risk-", suffix=suffix, delete=False) as handle:
        temp_path = Path(handle.name)
        upload.save(handle)

    try:
        report = analyze_image(temp_path)
        report.image_path = safe_name
        report.metadata["file_name"] = safe_name
        report.metadata.pop("file_path", None)
        return report
    finally:
        temp_path.unlink(missing_ok=True)


def _scan_local_lab() -> list[dict[str, object]]:
    results = []
    for host, base_url in LOCAL_LAB_HOSTS.items():
        host_result: dict[str, object] = {
            "host": host,
            "base_url": base_url,
            "status": "closed",
            "links": [],
            "images": [],
        }
        try:
            with urllib.request.urlopen(base_url, timeout=1.5) as response:
                html = response.read().decode("utf-8", errors="replace")
                host_result["status"] = "open"
                host_result["links"] = _extract_links(html, base_url)
                host_result["images"] = _discover_images(base_url)
        except urllib.error.URLError:
            pass
        results.append(host_result)
    return results


def _extract_links(html: str, base_url: str) -> list[str]:
    matches = re.findall(r'href="([^"]+)"', html, flags=re.IGNORECASE)
    return [urljoin(base_url, match) for match in matches if not match.startswith("?")]


def _discover_images(base_url: str) -> list[str]:
    visited: set[str] = set()
    pending = [base_url]
    images: list[str] = []
    image_extensions = tuple(ALLOWED_EXTENSIONS)

    while pending:
        url = pending.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            with urllib.request.urlopen(url, timeout=1.5) as response:
                content_type = response.headers.get("Content-Type", "")
                if "text/html" not in content_type:
                    if url.lower().endswith(image_extensions):
                        images.append(url)
                    continue
                html = response.read().decode("utf-8", errors="replace")
        except urllib.error.URLError:
            continue

        for link in _extract_links(html, url):
            if urlparse(link).netloc != urlparse(base_url).netloc:
                continue
            if link.lower().endswith(image_extensions):
                images.append(link)
            elif link.endswith("/"):
                pending.append(link)

    return sorted(set(images))


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
