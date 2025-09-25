from __future__ import annotations
import time, struct
from l2msg.core import protocol
from l2msg.net.raw_socket import RawLink
from l2msg.utils.ifaces import mac_to_str
from l2msg.storage.peers import PeerTable

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
    link.send(b"\xff\xff\xff\xff\xff\xff", frame)

def send_ack(link: RawLink, dst_mac: bytes, node_name: str, seq: int = 1):
    payload = build_payload_name(node_name)
    frame = protocol.pack_frame(protocol.HELLO_ACK, seq, payload)
    link.send(dst_mac, frame)

def discover(link: RawLink, node_name: str, peer_table: PeerTable, window_s: float = 1.5) -> dict[str, str]:
    t0 = time.monotonic()
    broadcast_hello(link, node_name, seq=int(t0) & 0xffffffff)

    while time.monotonic() - t0 < window_s:
        pkt = link.recv(timeout=0.2)
        if not pkt:
            continue

        src, _, p = pkt

        # ⬇️ Ignorar mis propias tramas (evita auto-registro)
        if src == link.src_mac:
            continue

        try:
            mtype, seq, flags, payload = protocol.unpack_frame(p)
        except Exception:
            continue

        mac = mac_to_str(src)
        if mtype == protocol.HELLO:
            # ⬇️ NUEVO: registrar a quien “saluda”
            name = parse_payload_name(payload)
            peer_table.add_peer(mac, name)
            # Responder unicast
            send_ack(link, src, node_name, seq=seq)

        elif mtype == protocol.HELLO_ACK:
            name = parse_payload_name(payload)
            peer_table.add_peer(mac, name)
    return peer_table.get_peers()

def listen_forever(link: RawLink, node_name: str, peer_table: PeerTable):
    #print(f"[listen] iface={link.iface} etype=0x{link.ether_type:04x} mac={mac_to_str(link.src_mac)}")
    while True:
        pkt = link.recv(timeout=1.0)
        if not pkt:
            continue

        src, _, p = pkt

        # ⬇️ Ignorar mis propias tramas
        if src == link.src_mac:
            continue

        try:
            mtype, seq, flags, payload = protocol.unpack_frame(p)
        except Exception:
            continue

        mac = mac_to_str(src)
        if mtype == protocol.HELLO:
            name = parse_payload_name(payload)
            #print(f"[discover<-] HELLO from {mac} name='{name}'")
            # ⬇️ NUEVO: registrar al emisor del HELLO
            peer_table.add_peer(mac, name)
            send_ack(link, src, node_name, seq)

        elif mtype == protocol.HELLO_ACK:
            name = parse_payload_name(payload)
            #print(f"[discover->] HELLO_ACK from {mac} name='{name}'")
            peer_table.add_peer(mac, name)