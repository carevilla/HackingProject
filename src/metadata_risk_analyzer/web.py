from __future__ import annotations

import tempfile
from pathlib import Path
import re
from urllib.parse import urljoin, urlparse
import urllib.error
import urllib.request

from flask import Flask, jsonify, render_template, request
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from .analyzer import analyze_image
from .correlate import build_timeline, cluster_locations, group_by_device
from .demo_data import DEMO_SCENARIOS, build_demo_report


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

        for upload in uploads:
            if not upload or not upload.filename:
                continue
            if not _is_valid_upload(upload):
                skipped += 1
                continue

            try:
                report = _analyze_upload(upload)
                reports.append(report.to_dict())
            except OSError as exc:
                errors.append(f"{upload.filename}: {exc}")

        if not reports and not errors:
            errors.append(
                "No supported images found. Choose one or more JPG/PNG/TIFF/WebP files, or a folder containing them."
            )

        return render_template(
            "index.html",
            reports=reports,
            errors=errors,
            demo_scenarios=DEMO_SCENARIOS,
            scan_results=None,
            ingest_summary=_summarize_ingest(reports, skipped),
            device_groups=group_by_device(reports),
            location_clusters=cluster_locations(reports),
            timeline=build_timeline(reports),
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
            device_groups=group_by_device(reports),
            location_clusters=cluster_locations(reports),
            timeline=build_timeline(reports),
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

    return app


def _is_valid_upload(upload: FileStorage) -> bool:
    if not upload or not upload.filename:
        return False
    extension = Path(upload.filename).suffix.lower()
    return extension in ALLOWED_EXTENSIONS


def _analyze_upload(upload: FileStorage):
    raw_name = upload.filename or "uploaded-image"
    suffix = Path(raw_name).suffix.lower()
    display_name = Path(raw_name).name or secure_filename(raw_name) or "uploaded-image"

    with tempfile.NamedTemporaryFile(prefix="metadata-risk-", suffix=suffix, delete=False) as handle:
        temp_path = Path(handle.name)
        upload.save(handle)

    try:
        report = analyze_image(temp_path)
        report.image_path = display_name
        report.metadata["file_name"] = display_name
        report.metadata.pop("file_path", None)
        return report
    finally:
        temp_path.unlink(missing_ok=True)


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