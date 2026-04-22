from __future__ import annotations

import functools
import http.server
import socketserver
import threading
from pathlib import Path


LAB_ROOT = Path(__file__).resolve().parent
ASSET_ROOT = LAB_ROOT / "host_assets"

HOSTS = {
    "alpha": 8001,
    "beta": 8002,
    "gamma": 8003,
    "archive": 8004,
}


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


def main() -> None:
    servers: list[ThreadedTCPServer] = []
    threads: list[threading.Thread] = []

    try:
        for host, port in HOSTS.items():
            host_dir = ASSET_ROOT / host
            handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(host_dir))
            server = ThreadedTCPServer(("127.0.0.1", port), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            servers.append(server)
            threads.append(thread)
            print(f"{host} serving {host_dir} at http://127.0.0.1:{port}")

        print()
        print("Localhost CTF lab is running. Press Ctrl+C to stop.")
        print("Try opening http://127.0.0.1:8001 in your browser.")

        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        print()
        print("Stopping localhost host servers...")
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
