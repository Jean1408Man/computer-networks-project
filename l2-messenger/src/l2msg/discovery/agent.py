from __future__ import annotations
import time, struct, os, logging, threading, zlib
from l2msg.core import protocol
from l2msg.net.raw_socket import RawLink
from l2msg.utils.ifaces import mac_to_str
from l2msg.storage.peers import PeerTable

log = logging.getLogger("agent.listen")
_incoming = {}
INBOX_DIR = os.getenv("L2MSG_INBOX", "/tmp/l2files")

# Payload HELLO/ACK: NAME_LEN(1) | NAME(bytes)
def build_payload_name(name: str) -> bytes:
    b = name.encode("utf-8")
    if len(b) > 255:
        b = b[:255]
    return struct.pack("!B", len(b)) + b

def parse_payload_name(payload: bytes) -> str:
    if not payload:
        return ""
    n = payload[0]
    return payload[1:1+n].decode("utf-8", errors="replace")

def broadcast_hello(link: RawLink, node_name: str, seq: int = 1):
    payload = build_payload_name(node_name)
    frame = protocol.pack_frame(protocol.HELLO, seq, payload)
    log.debug("Broadcast HELLO seq=%d name=%s", seq, node_name)
    link.send(b"\xff\xff\xff\xff\xff\xff", frame)

def send_ack(link: RawLink, dst_mac: bytes, node_name: str, seq: int = 1):
    payload = build_payload_name(node_name)
    frame = protocol.pack_frame(protocol.HELLO_ACK, seq, payload)
    log.debug("Enviando HELLO_ACK -> %s", mac_to_str(dst_mac))
    link.send(dst_mac, frame)

def discover(link: RawLink, node_name: str, peer_table: PeerTable, window_s: float = 1.5) -> dict[str, str]:
    t0 = time.monotonic()
    broadcast_hello(link, node_name, seq=int(t0) & 0xffffffff)

    while time.monotonic() - t0 < window_s:
        pkt = link.recv(timeout=0.2)
        if not pkt:
            continue

        src, _, p = pkt
        if src == link.src_mac:
            continue

        try:
            mtype, seq, flags, payload = protocol.unpack_frame(p)
        except Exception as e:
            log.warning("Trama inválida en discover: %s", e)
            continue

        mac = mac_to_str(src)
        if mtype == protocol.HELLO:
            name = parse_payload_name(payload)
            log.info("RX HELLO de %s name='%s'", mac, name)
            peer_table.add_peer(mac, name)
            send_ack(link, src, node_name, seq=seq)

        elif mtype == protocol.HELLO_ACK:
            name = parse_payload_name(payload)
            log.info("RX HELLO_ACK de %s name='%s'", mac, name)
            peer_table.add_peer(mac, name)

    return peer_table.get_peers()

def listen_forever(link: RawLink, node_name: str, peer_table: PeerTable, pause_event: 'threading.Event' = None):
    """
    Listener principal. Si pause_event está activo, NO llama a recv() para no competir
    con el emisor durante una transferencia.
    """
    log.info("Escuchando en iface=%s etype=0x%04x mac=%s",
             link.iface, link.ether_type, mac_to_str(link.src_mac))
    os.makedirs(INBOX_DIR, exist_ok=True)

    while True:
        # Pausa cooperativa: liberar el socket para el emisor (send_file)
        if pause_event is not None and pause_event.is_set():
            time.sleep(0.02)
            continue

        pkt = link.recv(timeout=1.0)
        if not pkt:
            continue

        src, _, p = pkt
        if src == link.src_mac:
            continue

        try:
            mtype, seq, flags, payload = protocol.unpack_frame(p)
        except Exception as e:
            log.warning("Trama inválida en listen_forever: %s", e)
            continue

        mac = mac_to_str(src)

        if mtype == protocol.HELLO:
            name = parse_payload_name(payload)
            log.info("RX HELLO de %s name='%s'", mac, name)
            peer_table.add_peer(mac, name)
            send_ack(link, src, node_name, seq)

        elif mtype == protocol.HELLO_ACK:
            name = parse_payload_name(payload)
            log.info("RX HELLO_ACK de %s name='%s'", mac, name)
            peer_table.add_peer(mac, name)

        elif mtype == protocol.FILE_OFFER:
            fname, fsize, crc_expected = protocol.parse_file_offer(payload)
            dst_path = f"{INBOX_DIR}/{fname}"
            log.info("RX FILE_OFFER de %s: %s (%d bytes, crc=0x%08x)", mac, fname, fsize, crc_expected)
            st = {
                "fp": open(dst_path, "wb"),
                "name": fname,
                "size": fsize,
                "bytes": 0,
                "expected": 0,           # próximo seq esperado
                "crc": 0,                # crc32 acumulado
                "crc_expected": crc_expected,
            }
            _incoming[mac] = st
            link.send(src, protocol.pack_frame(protocol.FILE_ACCEPT, seq, b""))
            log.debug("Enviado FILE_ACCEPT a %s", mac)
            peer_table.add_peer(mac, peer_table.get_peers().get(mac, {}).get("name", ""))

        elif mtype == protocol.FILE_DATA:
            st = _incoming.get(mac)
            if not st:
                log.warning("RX FILE_DATA inesperado de %s seq=%d -> CANCEL", mac, seq)
                link.send(src, protocol.pack_frame(protocol.FILE_CANCEL, seq, b""))
                continue

            exp = st["expected"]
            if seq < exp:
                # Duplicado (probable reintento por ACK perdido)
                log.debug("Duplicado de %s seq=%d (expected=%d) -> re-ACK sin escribir", mac, seq, exp)
                link.send(src, protocol.pack_frame(protocol.FILE_ACK, seq, b""))
                continue
            elif seq > exp:
                # Fuera de orden en stop-and-wait (no debería ocurrir)
                log.warning("Fuera de orden de %s seq=%d (expected=%d) -> ignorando y re-ACK", mac, seq, exp)
                link.send(src, protocol.pack_frame(protocol.FILE_ACK, seq, b""))
                continue

            # seq == expected -> escribir (respetando tamaño anunciado)
            remaining = st["size"] - st["bytes"]
            write_bytes = payload if len(payload) <= remaining else payload[:max(0, remaining)]
            if write_bytes:
                st["fp"].write(write_bytes)
                st["bytes"] += len(write_bytes)
                st["crc"] = zlib.crc32(write_bytes, st["crc"])
            st["expected"] += 1

            if seq == 0:
                log.info("RX primer FILE_DATA de %s (bytes=%d/%d)", mac, st["bytes"], st["size"])
            else:
                log.debug("RX FILE_DATA de %s seq=%d (%d/%d bytes)", mac, seq, st["bytes"], st["size"])

            # ACK del mismo seq
            link.send(src, protocol.pack_frame(protocol.FILE_ACK, seq, b""))
            log.debug("ACK seq=%d enviado a %s", seq, mac)

        elif mtype == protocol.FILE_DONE:
            st = _incoming.pop(mac, None)
            if st:
                st["fp"].close()
                rx_crc = None
                if len(payload) == 4:
                    (rx_crc,) = struct.unpack("!I", payload)
                # valida bytes y CRC (si vino en DONE o usa el del OFFER)
                expected_crc = rx_crc if rx_crc is not None else st["crc_expected"]
                ok = (st["bytes"] == st["size"]) and ((st["crc"] & 0xffffffff) == (expected_crc & 0xffffffff))
                log.info(
                    "RX FILE_DONE de %s -> archivo %s cerrado (%d/%d bytes, crc=0x%08x esperado=0x%08x) %s",
                    mac, st["name"], st["bytes"], st["size"],
                    st["crc"] & 0xffffffff, expected_crc & 0xffffffff,
                    "OK" if ok else "MISMATCH"
                )

        elif mtype == protocol.FILE_CANCEL:
            st = _incoming.pop(mac, None)
            if st:
                st["fp"].close()
                log.warning("RX FILE_CANCEL de %s -> archivo %s cancelado (%d bytes)",
                            mac, st["name"], st["bytes"])
