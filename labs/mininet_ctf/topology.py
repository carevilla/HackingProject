from __future__ import annotations

from pathlib import Path

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.topo import Topo


LAB_ROOT = Path(__file__).resolve().parent
HOST_ASSET_ROOT = LAB_ROOT / "host_assets"


class MetadataCTFTopo(Topo):
    def build(self):
        attacker = self.addHost("attacker", ip="10.0.0.10/24")
        alpha = self.addHost("alpha", ip="10.0.0.11/24")
        beta = self.addHost("beta", ip="10.0.0.12/24")
        gamma = self.addHost("gamma", ip="10.0.0.13/24")
        archive = self.addHost("archive", ip="10.0.0.14/24")

        switch = self.addSwitch("s1")
        for host in (attacker, alpha, beta, gamma, archive):
            self.addLink(host, switch)


def start_lab() -> None:
    net = Mininet(topo=MetadataCTFTopo(), switch=OVSSwitch)
    net.start()

    for host_name in ("alpha", "beta", "gamma", "archive"):
        host = net.get(host_name)
        asset_dir = HOST_ASSET_ROOT / host_name
        log_path = f"/tmp/{host_name}-http.log"
        host.cmd(f"cd {asset_dir} && python3 -m http.server 8000 > {log_path} 2>&1 &")

    _print_help()
    CLI(net)

    for host_name in ("alpha", "beta", "gamma", "archive"):
        host = net.get(host_name)
        host.cmd("pkill -f 'python3 -m http.server 8000'")

    net.stop()


def _print_help() -> None:
    print()
    print("Metadata CTF lab is running.")
    print("Try these commands inside the Mininet prompt:")
    print("  pingall")
    print("  attacker curl http://10.0.0.11:8000/")
    print("  attacker python3 labs/mininet_ctf/collector.py /tmp/loot")
    print("  attacker python3 run_cli.py /tmp/loot/*.jpg")
    print()


if __name__ == "__main__":
    setLogLevel("info")
    start_lab()
