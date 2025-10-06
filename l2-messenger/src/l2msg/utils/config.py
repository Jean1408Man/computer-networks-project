from __future__ import annotations
import os, pathlib, tomllib, re

DEFAULTS = {
    "ether_type": "0x88B5",
    "iface": "auto",
    "node_name": "node",
    "mtu_safe": 1400,
}

def load_config(path: str | None = None) -> dict:
    # Busca configs/app.toml por defecto
    base = pathlib.Path(os.environ.get("L2MSG_CONFIG", path or "configs/app.toml"))
    if not base.exists():
        # fallback a example
        base = pathlib.Path("configs/app.example.toml")
    with base.open("rb") as f:
        data = tomllib.load(f)
    app = {**DEFAULTS, **(data.get("app") or {})}
    # Normaliza EtherType
    et = app["ether_type"]
    if isinstance(et, str):
        if et.lower().startswith("0x"):
            app["ether_type"] = int(et, 16)
        else:
            app["ether_type"] = int(et)

    app["crypto"] = data.get("crypto", {})
    app["logging"] = data.get("logging", {})

    return app
