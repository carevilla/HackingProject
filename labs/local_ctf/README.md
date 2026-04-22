# Localhost CTF Lab

This is a macOS-friendly version of the network lab.

Instead of Mininet, it runs several local HTTP servers on different ports. Each one acts like a separate host and serves an image with different metadata.

## Idea

- `alpha` runs on `127.0.0.1:8001`
- `beta` runs on `127.0.0.1:8002`
- `gamma` runs on `127.0.0.1:8003`
- `archive` runs on `127.0.0.1:8004`

An attacker script downloads the exposed images, then you analyze them with the metadata risk analyzer.

## Files

- `generate_demo_assets.py`: creates the sample images and host web pages
- `start_hosts.py`: starts all localhost host servers at once
- `scanner.py`: probes the fake hosts and can list exposed links
- `collector.py`: downloads images from each host into a loot folder

## Install Requirements

From the project root:

```bash
source .venv/bin/activate
pip install Pillow
```

## Generate Demo Assets

```bash
python labs/local_ctf/generate_demo_assets.py
```

That creates:

```text
labs/local_ctf/host_assets/
├── alpha/
├── beta/
├── gamma/
└── archive/
```

## Start The Fake Hosts

```bash
python labs/local_ctf/start_hosts.py
```

Keep that terminal open while the servers are running.

You should see:

- `http://127.0.0.1:8001`
- `http://127.0.0.1:8002`
- `http://127.0.0.1:8003`
- `http://127.0.0.1:8004`

## Collect The Images

In a second terminal:

```bash
source .venv/bin/activate
python labs/local_ctf/scanner.py
python labs/local_ctf/scanner.py --links
python labs/local_ctf/scanner.py --images
python labs/local_ctf/collector.py labs/local_ctf/loot
```

The scanner and collector discover image links by walking host pages, so some hosts can hide files inside subdirectories and still be found.

## Analyze The Loot

```bash
python run_cli.py labs/local_ctf/loot/*.jpg
```

You can also use the web app:

1. Start `python run_web.py`
2. Click `Run Lab Scan`
3. Click `Analyze Collected Loot`

## Nice Demo Flow

1. Start the localhost host servers.
2. Visit one of the host pages in the browser.
3. Run the collector script to simulate the attacker.
4. Run the metadata analyzer on the downloaded files.
5. Compare which host leaked the most dangerous metadata.

## Optional CTF Framing

You can present this as:

"We simulated a small network of hosts exposing images, then used an attacker workflow to collect and analyze them for privacy-risking metadata."
