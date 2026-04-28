from __future__ import annotations

import io
import tempfile
import uuid
from pathlib import Path
import re
from urllib.parse import urljoin, urlparse
import urllib.error
import urllib.request

from flask import Flask, jsonify, render_template, request, send_file
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from . import spoofer
from .analyzer import analyze_image
from .correlate import build_sort_keys, build_timeline, cluster_locations, group_by_device
from .demo_data import DEMO_SCENARIOS, build_demo_report
from .forensics import analyze_thumbnail, analyze_tampering
from .geocoder import reverse_geocode


ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".tiff", ".tif", ".webp"}
LOCAL_LAB_HOSTS = {
    # Subnet A — behind switch s1 (via edge router r2)
    "alpha":   "http://127.0.0.1:8001/",
    "beta":    "http://127.0.0.1:8002/",
    "gamma":   "http://127.0.0.1:8003/",
    "archive": "http://127.0.0.1:8004/",
    # Subnet B — behind switch s2 (via core router r1 directly)
    "delta":   "http://127.0.0.1:8005/",
    "epsilon": "http://127.0.0.1:8006/",
    "zeta":    "http://127.0.0.1:8007/",
    "omega":   "http://127.0.0.1:8008/",
}

# Which switch each host sits behind (drives topology graph)
HOST_SUBNET: dict[str, str] = {
    "alpha": "s1", "beta": "s1", "gamma": "s1", "archive": "s1",
    "delta": "s2", "epsilon": "s2", "zeta": "s2", "omega": "s2",
}
LOCAL_LOOT_DIR = Path("labs/local_ctf/loot")

# ── In-memory store for user-added nodes / routers ───────────────────────────
_custom_nodes: list[dict] = []
_custom_links: list[dict] = []

# ── Persistent temp store for the most-recent batch of uploaded images so the
# per-card spoof form can re-read the original bytes. Each new /analyze or
# /lab/loot call wipes the previous batch, capping disk usage at one batch.
_UPLOAD_STORE_DIR = Path(tempfile.gettempdir()) / "metadata_risk_uploads"
_UPLOAD_STORE_DIR.mkdir(parents=True, exist_ok=True)
_uploaded_images: dict[str, dict] = {}  # upload_id -> {"path": Path, "filename": str}


def _clear_upload_store() -> None:
    for entry in _uploaded_images.values():
        try:
            entry["path"].unlink(missing_ok=True)
        except OSError:
            pass
    _uploaded_images.clear()


def _store_upload_bytes(image_bytes: bytes, original_name: str) -> str:
    upload_id = uuid.uuid4().hex
    suffix = Path(original_name).suffix.lower() or ".bin"
    path = _UPLOAD_STORE_DIR / f"{upload_id}{suffix}"
    path.write_bytes(image_bytes)
    _uploaded_images[upload_id] = {"path": path, "filename": original_name}
    return upload_id


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 256 * 1024 * 1024

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
        skipped = 0

        # Wipe the previous batch so disk usage is bounded to one batch at a
        # time. The per-card spoof form references upload_ids from this batch.
        _clear_upload_store()

        for upload in uploads:
            if not upload or not upload.filename:
                continue
            if not _is_valid_upload(upload):
                skipped += 1
                continue

            try:
                report_dict = _analyze_upload(upload)
                reports.append(report_dict)
            except OSError as exc:
                errors.append(f"{upload.filename}: {exc}")

        if not reports and not errors:
            errors.append(
                "No supported images found. Choose one or more JPG/PNG/TIFF/WebP files, or a folder containing them."
            )

        device_groups = group_by_device(reports)
        location_clusters = cluster_locations(reports)
        _enrich_with_addresses(reports, location_clusters)
        return render_template(
            "index.html",
            reports=reports,
            errors=errors,
            demo_scenarios=DEMO_SCENARIOS,
            scan_results=None,
            ingest_summary=_summarize_ingest(reports, skipped),
            device_groups=device_groups,
            location_clusters=location_clusters,
            timeline=build_timeline(reports),
            sort_keys=build_sort_keys(reports, device_groups, location_clusters),
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

        _clear_upload_store()

        if not LOCAL_LOOT_DIR.exists():
            errors.append("No local loot folder found yet. Run the collector first.")
        else:
            for path in sorted(LOCAL_LOOT_DIR.iterdir()):
                if not path.is_file() or path.suffix.lower() not in ALLOWED_EXTENSIONS:
                    continue
                try:
                    upload_id = _store_upload_bytes(path.read_bytes(), path.name)
                    stored_path = _uploaded_images[upload_id]["path"]
                    report = analyze_image(stored_path)
                    report.image_path = path.name
                    report.metadata["file_name"] = path.name
                    report.metadata.pop("file_path", None)
                    rd = report.to_dict()
                    rd["upload_id"] = upload_id
                    rd["spoofable"] = stored_path.suffix.lower() in spoofer.SUPPORTED_EXTENSIONS
                    thumb = analyze_thumbnail(stored_path)
                    rd["thumbnail_diff"] = thumb.to_dict()
                    rd["tampering"] = analyze_tampering(report.metadata, thumb).to_dict()
                    reports.append(rd)
                except OSError as exc:
                    errors.append(f"{path.name}: {exc}")

            if not reports and not errors:
                errors.append("The loot folder exists, but no supported image files were found.")

        device_groups = group_by_device(reports)
        location_clusters = cluster_locations(reports)
        _enrich_with_addresses(reports, location_clusters)
        return render_template(
            "index.html",
            reports=reports,
            errors=errors,
            demo_scenarios=DEMO_SCENARIOS,
            scan_results=_scan_local_lab(),
            device_groups=device_groups,
            location_clusters=location_clusters,
            timeline=build_timeline(reports),
            sort_keys=build_sort_keys(reports, device_groups, location_clusters),
        )

    @app.get("/lab/network")
    def lab_network():
        scan = _scan_local_lab()
        open_count  = sum(1 for h in scan if h["status"] == "open")
        total_count = len(scan)

        nodes = [
            {"id": "scanner", "label": "Scanner\n(you)", "type": "attacker",
             "status": "active", "detail": "Your local machine — initiating scans", "builtin": True},
            {"id": "r1", "label": "Router r1\n(core)", "type": "router",
             "status": "active",
             "detail": f"Core router — {open_count}/{total_count} hosts reachable across both subnets",
             "builtin": True},
            {"id": "r2", "label": "Router r2\n(edge)", "type": "router",
             "status": "active", "detail": "Edge router — fronts Subnet A (s1) behind NAT", "builtin": True},
            {"id": "s1", "label": "Switch s1\nSubnet A", "type": "switch",
             "status": "active", "detail": "10.0.1.0/24 — alpha, beta, gamma, archive", "builtin": True},
            {"id": "s2", "label": "Switch s2\nSubnet B", "type": "switch",
             "status": "active", "detail": "10.0.2.0/24 — delta, epsilon, zeta, omega", "builtin": True},
        ]

        links = [
            {"source": "scanner", "target": "r1"},
            {"source": "r1",      "target": "r2"},
            {"source": "r1",      "target": "s2"},
            {"source": "r2",      "target": "s1"},
        ]

        for host in scan:
            image_count = len(host.get("images", []))
            link_count  = len(host.get("links",  []))
            switch_id   = HOST_SUBNET.get(host["host"], "s1")
            nodes.append({
                "id":     host["host"],
                "label":  host["host"],
                "type":   "host",
                "status": host["status"],
                "detail": f"{host['base_url']} · {image_count} image(s) · {link_count} link(s)",
                "url":    host["base_url"],
                "images": image_count,
                "links":  link_count,
                "builtin": True,
            })
            links.append({"source": switch_id, "target": host["host"]})

        nodes.extend(_custom_nodes)
        links.extend(_custom_links)

        return jsonify({"nodes": nodes, "links": links})

    # ── Custom node management ────────────────────────────────────────────────

    @app.post("/lab/network/node")
    def add_network_node():
        data = request.get_json(force=True)
        node_id    = (data.get("id") or "").strip()
        label      = (data.get("label") or node_id).strip()
        node_type  = data.get("type", "host")
        detail     = data.get("detail", "User-added node")
        connect_to = (data.get("connect_to") or "").strip()

        if not node_id:
            return jsonify({"error": "id is required"}), 400

        builtin_ids = {"scanner", "r1", "r2", "s1", "s2"} | set(LOCAL_LAB_HOSTS.keys())
        existing_ids = {n["id"] for n in _custom_nodes} | builtin_ids
        if node_id in existing_ids:
            return jsonify({"error": f"Node '{node_id}' already exists"}), 409

        if node_type not in ("host", "router", "switch"):
            return jsonify({"error": "type must be host, router, or switch"}), 400

        new_node = {
            "id":      node_id,
            "label":   label,
            "type":    node_type,
            "status":  "active" if node_type in ("router", "switch") else "unknown",
            "detail":  detail,
            "builtin": False,
        }
        _custom_nodes.append(new_node)

        if connect_to:
            _custom_links.append({"source": connect_to, "target": node_id})

        return jsonify({"ok": True, "node": new_node}), 201

    @app.delete("/lab/network/node/<node_id>")
    def delete_network_node(node_id):
        before = len(_custom_nodes)
        _custom_nodes[:] = [n for n in _custom_nodes if n["id"] != node_id]
        _custom_links[:] = [
            lk for lk in _custom_links
            if lk["source"] != node_id and lk["target"] != node_id
        ]
        if len(_custom_nodes) == before:
            return jsonify({"error": "Node not found or is built-in"}), 404
        return jsonify({"ok": True}), 200

    @app.get("/lab/network/nodes")
    def list_all_node_ids():
        builtin_ids = ["scanner", "r1", "r2", "s1", "s2"] + list(LOCAL_LAB_HOSTS.keys())
        custom_ids  = [n["id"] for n in _custom_nodes]
        return jsonify({"all_ids": builtin_ids + custom_ids, "custom": _custom_nodes})

    @app.get("/raw/<upload_id>")
    def raw_image(upload_id):
        entry = _uploaded_images.get(upload_id)
        if not entry or not entry["path"].exists():
            return jsonify({"error": "Image is no longer available — re-analyze the batch."}), 404
        # Serve as attachment so the browser triggers a download — the user
        # then drags this file into a reverse-image-search engine tab.
        return send_file(
            str(entry["path"]),
            as_attachment=True,
            download_name=entry["filename"],
        )

    @app.post("/spoof/<upload_id>")
    def spoof_stored_image(upload_id):
        entry = _uploaded_images.get(upload_id)
        if not entry:
            return jsonify({"error": "Image is no longer available — re-analyze the batch."}), 404

        path = entry["path"]
        if not path.exists():
            return jsonify({"error": "Stored image is missing on disk."}), 404
        if path.suffix.lower() not in spoofer.SUPPORTED_EXTENSIONS:
            return jsonify({"error": "Spoofer supports JPEG only."}), 415

        image_bytes = path.read_bytes()
        mode = request.form.get("mode", "spoof")

        try:
            if mode == "sanitize":
                new_bytes = spoofer.sanitize(image_bytes)
                suffix_label = "_sanitized"
            else:
                overrides = {
                    "make":              (request.form.get("make") or "").strip() or None,
                    "model":             (request.form.get("model") or "").strip() or None,
                    "software":          (request.form.get("software") or "").strip() or None,
                    "datetime_original": (request.form.get("datetime_original") or "").strip() or None,
                    "latitude":          _try_float(request.form.get("latitude")),
                    "longitude":         _try_float(request.form.get("longitude")),
                    "strip_gps":         request.form.get("strip_gps") in ("on", "true", "1"),
                    "strip_serials":     request.form.get("strip_serials") in ("on", "true", "1"),
                }
                lat, lon = overrides["latitude"], overrides["longitude"]
                if (lat is None) != (lon is None):
                    return jsonify({"error": "Provide both latitude and longitude, or neither."}), 400
                new_bytes = spoofer.spoof(image_bytes, overrides)
                suffix_label = "_spoofed"
        except spoofer.SpoofError as exc:
            return jsonify({"error": str(exc)}), 400

        stem = Path(secure_filename(entry["filename"])).stem or "image"
        download_name = f"{stem}{suffix_label}.jpg"
        return send_file(
            io.BytesIO(new_bytes),
            mimetype="image/jpeg",
            as_attachment=True,
            download_name=download_name,
        )

    return app


def _try_float(value):
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _is_valid_upload(upload: FileStorage) -> bool:
    if not upload or not upload.filename:
        return False
    extension = Path(upload.filename).suffix.lower()
    return extension in ALLOWED_EXTENSIONS


def _analyze_upload(upload: FileStorage) -> dict:
    raw_name = upload.filename or "uploaded-image"
    display_name = Path(raw_name).name or secure_filename(raw_name) or "uploaded-image"

    image_bytes = upload.read()
    upload_id = _store_upload_bytes(image_bytes, display_name)
    stored_path = _uploaded_images[upload_id]["path"]

    report = analyze_image(stored_path)
    report.image_path = display_name
    report.metadata["file_name"] = display_name
    report.metadata.pop("file_path", None)
    report_dict = report.to_dict()
    report_dict["upload_id"] = upload_id
    report_dict["spoofable"] = stored_path.suffix.lower() in spoofer.SUPPORTED_EXTENSIONS
    thumb = analyze_thumbnail(stored_path)
    report_dict["thumbnail_diff"] = thumb.to_dict()
    report_dict["tampering"] = analyze_tampering(report.metadata, thumb).to_dict()
    return report_dict


def _enrich_with_addresses(reports: list[dict], location_clusters: list[dict], max_unique_lookups: int = 25) -> None:
    """Reverse-geocode cluster centroids and per-image GPS coords in place.

    The geocoder cache means many calls become no-ops (folder of photos at the
    same hotspot only triggers one network request). To bound latency on huge
    batches we still cap *new* lookups at `max_unique_lookups`; remaining
    coordinates fall through to whatever the cache happens to have.
    """
    seen_keys: set[tuple[float, float]] = set()
    new_lookups = 0

    def lookup_capped(lat, lon):
        nonlocal new_lookups
        if lat is None or lon is None:
            return None
        try:
            key = (round(float(lat), 3), round(float(lon), 3))
        except (TypeError, ValueError):
            return None
        if key in seen_keys:
            return reverse_geocode(lat, lon)
        if new_lookups >= max_unique_lookups:
            return None
        seen_keys.add(key)
        new_lookups += 1
        return reverse_geocode(lat, lon)

    # Cluster centroids first — most informative and small in number
    for cluster in location_clusters:
        cluster["address"] = lookup_capped(cluster.get("centroid_lat"), cluster.get("centroid_lon"))

    # Per-image lookups (cluster-adjacent photos hit the cache)
    for report in reports:
        meta = report.get("metadata") or {}
        report["address"] = lookup_capped(meta.get("gps_latitude"), meta.get("gps_longitude"))

    # Propagate addresses into cluster.images so the Leaflet popups can show them
    address_by_index: dict[int, dict] = {
        i: r["address"] for i, r in enumerate(reports) if r.get("address")
    }
    for cluster in location_clusters:
        for img in cluster.get("images", []):
            addr = address_by_index.get(img["index"]) or cluster.get("address")
            if addr:
                img["address"] = addr


def _summarize_ingest(reports: list, skipped: int) -> dict[str, int] | None:
    if not reports and not skipped:
        return None
    high_risk = sum(1 for r in reports if r.get("risk_level") in ("High", "Critical"))
    with_gps = sum(
        1 for r in reports
        if r.get("metadata", {}).get("gps_latitude") is not None
        and r.get("metadata", {}).get("gps_longitude") is not None
    )
    return {
        "analyzed": len(reports),
        "skipped": skipped,
        "high_risk": high_risk,
        "with_gps": with_gps,
    }


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