# Mininet CTF Lab

This lab turns the metadata analyzer into a small network-based exercise.

## Idea

Each Mininet host exposes one image over HTTP.
An attacker host can discover or directly fetch those images across the lab network.
After collecting them, students run the metadata analyzer to see which host leaked the riskiest metadata.

## Topology

```text
                s1
        /    /   |   \    \
 attacker alpha beta gamma archive
```

- `attacker`: collection box used to fetch images
- `alpha`: serves a low-risk image
- `beta`: serves an image with timestamps and device fields
- `gamma`: serves an image with serial and owner-like fields
- `archive`: serves another image that can act as a decoy

Each victim host runs `python3 -m http.server 8000` inside its own asset directory.

## Important Environment Note

Mininet is usually run on Linux. It is not installed in this workspace right now.

If you are on macOS, the easiest path is:

1. Use an Ubuntu VM.
2. Clone or copy this project into that VM.
3. Install Mininet there.

## Files

- `topology.py`: starts the network and launches per-host HTTP servers
- `generate_demo_assets.py`: creates sample JPEGs with metadata in each host folder
- `collector.py`: downloads images from the victim hosts

## Install In A Linux VM

Example Ubuntu setup:

```bash
sudo apt update
sudo apt install -y mininet python3-pip
python3 -m pip install Pillow
```

## Generate Demo Assets

Run this once before starting the network:

```bash
cd /path/to/HackingProject
python3 labs/mininet_ctf/generate_demo_assets.py
```

That creates:

```text
labs/mininet_ctf/host_assets/
├── alpha/leaked_alpha.jpg
├── beta/leaked_beta.jpg
├── gamma/leaked_gamma.jpg
└── archive/leaked_archive.jpg
```

## Start The Network

```bash
cd /path/to/HackingProject
sudo python3 labs/mininet_ctf/topology.py
```

Once Mininet opens, test reachability:

```bash
mininet> pingall
```

## Simulate The Attacker

From the Mininet CLI:

```bash
mininet> attacker curl http://10.0.0.11:8000/
mininet> attacker python3 labs/mininet_ctf/collector.py /tmp/loot
mininet> attacker ls -R /tmp/loot
```

## Analyze The Loot

Still from the Mininet CLI:

```bash
mininet> attacker python3 run_cli.py /tmp/loot/*.jpg
```

Or after copying the files out of the VM:

```bash
python run_cli.py path/to/downloaded1.jpg path/to/downloaded2.jpg
```

## CTF Twist Ideas

- Rename image files so they do not obviously match the host.
- Put one image in a non-root folder and force basic enumeration.
- Make one host expose a directory listing and another require a guessed filename.
- Add a simple hint file on one host that points to another.
- Give students a question like: "Which host most likely reveals a home or work pattern?"

## Nice Demo Flow

1. Start Mininet.
2. Show `attacker` collecting images from the network.
3. Run the metadata analyzer on the collected files.
4. Compare risk scores and explain the privacy implications.
