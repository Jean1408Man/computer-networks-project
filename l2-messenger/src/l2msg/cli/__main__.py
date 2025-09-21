#!/usr/bin/env python3
from __future__ import annotations
import argparse, sys
from l2msg.utils.config import load_config
from l2msg.utils.ifaces import normalize_iface, mac_to_str
from l2msg.net.raw_socket import RawLink
from l2msg.discovery.agent import discover, listen_forever

def main() -> int:
    ap = argparse.ArgumentParser(prog="l2msg", description="Mensajería L2 (descubrimiento mínimo)")
    ap.add_argument("command", choices=["listen", "discover"], help="Acción a ejecutar")
    ap.add_argument("--config", default="configs/app.toml", help="Ruta al archivo TOML")
    args = ap.parse_args()

    cfg = load_config(args.config)
    iface = normalize_iface(cfg["iface"])
    etype = int(cfg["ether_type"])
    node_name = cfg["node_name"]

    link = RawLink(iface=iface, ether_type=etype)
    try:
        if args.command == "listen":
            listen_forever(link, node_name)
        elif args.command == "discover":
            peers = discover(link, node_name, window_s=1.5)
            if not peers:
                print("No se encontraron peers en la ventana de tiempo.")
            else:
                print("Peers encontrados:")
                for mac, name in peers.items():
                    print(f"  {mac}  {name}")
    finally:
        link.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())
