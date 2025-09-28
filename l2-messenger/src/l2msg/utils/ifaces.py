from __future__ import annotations
import os, pathlib

def list_ifaces() -> list[str]:
    root = pathlib.Path("/sys/class/net")
    return [p.name for p in root.iterdir() if p.is_dir()]

def get_mac_address(iface: str) -> bytes:
    addr_path = f"/sys/class/net/{iface}/address"
    with open(addr_path, "r", encoding="utf-8") as f:
        txt = f.read().strip()
    return bytes.fromhex(txt.replace(":", ""))

def choose_iface_auto() -> str:
    for name in list_ifaces():
        if name == "lo":
            continue
        # Excluimos interfaces sin dirección MAC válida
        try:
            _ = get_mac_address(name)
            return name
        except Exception:
            continue
    raise RuntimeError("No se encontró interfaz válida para 'auto'")

def normalize_iface(iface: str) -> str:
    return choose_iface_auto() if iface == "auto" else iface

def mac_to_str(mac: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac)
