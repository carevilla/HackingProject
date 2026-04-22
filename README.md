# Metadata Risk Analyzer

A Python project that analyzes image metadata and turns it into a practical privacy-risk report.

This first version focuses on:

- extracting EXIF and basic file metadata
- scoring privacy risk
- explaining why the metadata matters
- generating simple attack scenarios such as location inference and routine tracking

## Why this project is strong

Instead of just stripping metadata, this project helps users understand:

- what data is inside an image
- what an attacker could infer from it
- how risk changes across different metadata combinations

That makes it a good school project because it connects:

- digital forensics
- privacy engineering
- threat modeling
- beginner-friendly Python development

## Project Structure

```text
HackingProject/
├── pyproject.toml
├── README.md
├── src/
│   └── metadata_risk_analyzer/
│       ├── __init__.py
│       ├── __main__.py
│       ├── analyzer.py
│       ├── cli.py
│       ├── extractors.py
│       ├── models.py
│       ├── reporting.py
│       ├── web.py
│       ├── static/
│       │   └── styles.css
│       └── templates/
│           └── index.html
└── tests/
    └── test_analyzer.py
```

## Simple Architecture

1. `extractors.py`
   Reads image files and pulls EXIF plus file-level metadata.
2. `analyzer.py`
   Converts raw metadata into findings, a risk score, and attack scenarios.
3. `reporting.py`
   Formats reports as text or JSON-friendly data.
4. `cli.py`
   Lets users analyze one or more images from the terminal.
5. `web.py`
   Provides a simple upload-based web interface for demos.

## Getting Started

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install Flask Pillow
```

## Run The Web App

Start the browser interface:

```bash
python run_web.py
```

Then open:

```text
http://127.0.0.1:5000
```

You can upload one or more images and the app will show:

- risk score and level
- privacy findings
- attack scenarios
- extracted metadata preview

## Run The CLI

Analyze one or more images from the terminal:

```bash
python run_cli.py path/to/photo.jpg
python run_cli.py path/to/photo1.jpg path/to/photo2.jpg --json
```

If you want to use the installed package version instead, you can still do that after a normal install:

```bash
pip install .
python -m metadata_risk_analyzer path/to/photo.jpg
```

Run tests after installing dev tools:

```bash
pip install pytest
python -m pytest -q
```

## Current Features

- Basic EXIF extraction using Pillow
- GPS detection and decimal coordinate conversion
- Timestamp detection
- Device fingerprinting indicators
- Serial and unique ID checks
- Human-readable privacy findings
- Risk levels: Low, Moderate, High, Critical

## Example Output

```text
== beach_photo.jpg ==
Risk score: 75/100 (High)

Findings:
- GPS coordinates found: precise location can be inferred.
- Original timestamp found: image capture time can support timeline analysis.
- Device model found: images may be linkable to the same device.

Attack scenarios:
- Home location inference: repeated GPS-tagged photos can reveal home, work, or school.
- Routine tracking: timestamps across images can expose habits and movement patterns.
```

## Good Extension Ideas

- Reverse geolocation from GPS tags
- Timeline reconstruction across many photos
- Device correlation across multiple uploads
- Mininet-based CTF lab where an attacker host collects leaked images across a small network
- Metadata redaction recommendations
- Risk weighting tuned by research or user role

## Notes for a School Demo

If you want to keep the scope manageable, demo this in three phases:

1. Upload or pass an image file.
2. Show extracted metadata and privacy findings.
3. Explain the risk score and attack scenarios in plain language.

That gives you a practical MVP now while keeping room for a stronger final presentation later.

## Optional Mininet Lab

There is also a starter network lab in [labs/mininet_ctf/README.md](/Users/chrisrevilla/Documents/HackingProject/labs/mininet_ctf/README.md).

It is designed for a Linux VM with Mininet installed and lets you:

- assign an image to each host
- expose those images over HTTP
- simulate an attacker collecting them
- run the metadata analyzer on the captured files

## macOS Localhost Lab

If you are on a Mac, use the localhost version in [labs/local_ctf/README.md](/Users/chrisrevilla/Documents/HackingProject/labs/local_ctf/README.md).

It gives you the same basic demo flow without Mininet:

- multiple fake hosts on different localhost ports
- one image per host
- an attacker collection script
- analysis of the downloaded images

You can also launch the full Mac demo setup in one step:

```bash
chmod +x launch_demo.sh
./launch_demo.sh
```

That opens Terminal windows for:

- localhost host servers
- the web app
- an attacker terminal ready for scans and collection
# HackingProject
