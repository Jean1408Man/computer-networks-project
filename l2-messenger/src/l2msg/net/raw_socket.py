# raw_socket.py — stub (AF_PACKET, bind a interfaz, selección por EtherType, etc.)
from __future__ import annotations
import socket, struct, select, time
from l2msg.utils.ifaces import get_mac_address

# Cabecera Ethernet: DST(6) | SRC(6) | EtherType(2)
_ETH = struct.Struct("!6s6sH")

class RawLink:
    def __init__(self, iface: str, ether_type: int):
        self.iface = iface
        self.ether_type = ether_type
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ether_type))
        # Bind a la interfaz; 0 = todos los protocolos, pero el filtro ya es por proto del socket
        self.sock.bind((iface, 0))
        self.src_mac = get_mac_address(iface)

    def close(self):
        try: self.sock.close()
        except Exception: pass

    def send(self, dst_mac: bytes, payload: bytes) -> int:
        frame = _ETH.pack(dst_mac, self.src_mac, self.ether_type) + payload
        return self.sock.send(frame)

    def recv(self, timeout: float = 1.0):
        r, _, _ = select.select([self.sock], [], [], timeout)
        if not r:
            return None
        data = self.sock.recv(65535)
        if len(data) < _ETH.size:
            return None
        dst, src, et = _ETH.unpack_from(data, 0)
        if et != self.ether_type:
            return None
        l2payload = data[_ETH.size:]
        return src, dst, l2payload
