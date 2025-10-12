from __future__ import annotations
import struct, zlib

MAGIC = b"L2MG"
VERSION = 1

FLAG_ENC = 0x01  # payload cifrado/autenticado

# Tipos de mensaje mínimos para descubrimiento
HELLO     = 0x01
HELLO_ACK = 0x02
FILE_OFFER  = 0x10
FILE_ACCEPT = 0x11
FILE_DATA   = 0x12
FILE_ACK    = 0x13
FILE_DONE   = 0x14
FILE_CANCEL = 0x15
MSG_OFFER  = 0x20
MSG_ACCEPT = 0x21
MSG_DATA   = 0x22
MSG_ACK    = 0x23
MSG_DONE   = 0x24
MSG_CANCEL = 0x25
# Cabecera de nuestro protocolo (sobre el payload de Ethernet)
# MAGIC(4) | VER(1) | TYPE(1) | SEQ(4) | LEN(2) | FLAGS(1) | CRC32(4)
_HDR = struct.Struct("!4s B B I H B I")
HDR_LEN = _HDR.size  # 17 bytes
_MIN_ETH_PAYLOAD = 46  # mínimo de bytes de "payload Ethernet" (sin contar cabecera Ethernet)

def pack_frame(msg_type: int, seq: int, payload: bytes, flags: int = 0) -> bytes:
    """
    Empaqueta frame L2MG. El CRC se calcula SOLO sobre 'payload'.
    (Opcional) Si el total (cabecera+payload) < 46 bytes, pad hasta 46 para
    evitar rarezas con NICs cuando el payload es muy pequeño (ACK/ACCEPT cifrados).
    """
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError("payload debe ser bytes-like")

    plen = len(payload)
    if plen > 0xFFFF:
        raise ValueError(f"LEN demasiado grande para campo de 16 bits: {plen}")

    crc = zlib.crc32(payload) & 0xffffffff
    header = _HDR.pack(MAGIC, VERSION, msg_type, seq, plen, flags, crc)
    frame = header + payload

    # --- OPCIONAL: padding a mínimo Ethernet payload ---
    # Ethernet exige mínimo 46B de payload L2. Si nuestra (cabecera+payload)
    # es menor, añadimos ceros. El receptor los ignorará porque corta por 'LEN'.
    if len(frame) < _MIN_ETH_PAYLOAD:
        frame += b"\x00" * (_MIN_ETH_PAYLOAD - len(frame))

    return frame


def unpack_frame(data: bytes):
    total = len(data)
    if total < HDR_LEN:
        raise ValueError(f"frame demasiado corto: total={total} < HDR_LEN={HDR_LEN}")

    magic, ver, mtype, seq, plen, flags, crc_hdr = _HDR.unpack_from(data, 0)
    if magic != MAGIC:
        raise ValueError(f"MAGIC inválido: {magic!r} != {MAGIC!r}")
    if ver != VERSION:
        raise ValueError(f"VERSIÓN inválida: {ver} (esperado {VERSION})")
    if plen < 0 or plen > 0xFFFF:
        raise ValueError(f"LEN inválido/sospechoso: {plen}")

    start = HDR_LEN
    end   = start + plen
    if total < end:
        raise ValueError(f"LEN no coincide: declarada={plen}, disponible={total - HDR_LEN}")

    payload = memoryview(data)[start:end]  # ignorar padding más allá de LEN
    crc_calc = zlib.crc32(payload) & 0xffffffff
    if crc_calc != (crc_hdr & 0xffffffff):
        raise ValueError(f"CRC inválido (calc=0x{crc_calc:08x} hdr=0x{crc_hdr:08x}, plen={plen}, total={total})")

    return mtype, seq, flags, payload.tobytes()



def build_file_offer(name: str, size: int, hash32: int = 0) -> bytes:
    """
    Payload FILE_OFFER:
      NAME_LEN(1) | NAME(bytes) | SIZE(8, uint64) | CRC32(4, uint32)
    """
    b = name.encode("utf-8")[:255]
    return struct.pack("!B", len(b)) + b + struct.pack("!QI", size, hash32 & 0xffffffff)

def parse_file_offer(p: bytes):
    """
    Devuelve: (name, size:uint64, crc32:uint32)
    """
    if not p:
        return "", 0, 0
    n = p[0]
    name = p[1:1+n].decode("utf-8", "replace")
    size, h = struct.unpack_from("!QI", p, 1+n)
    return name, size, h

def build_msg_offer(size: int, hash32: int = 0) -> bytes:
    """
    Payload MSG_OFFER:
      SIZE(8, uint64) | CRC32(4, uint32)
    """
    return struct.pack("!QI", size, hash32 & 0xffffffff)

def parse_msg_offer(p: bytes):
    """
    Devuelve: (size:uint64, crc32:uint32)
    """
    if len(p) < 12:
        return 0, 0
    size, h = struct.unpack_from("!QI", p, 0)
    return size, h


def build_msg_offer(size: int, hash32: int = 0) -> bytes:
    """Payload MSG_OFFER: SIZE(8) | CRC32(4) del mensaje completo en claro"""
    return struct.pack("!QI", size, hash32 & 0xffffffff)

def parse_msg_offer(p: bytes):
    """Devuelve: (size:uint64, crc32:uint32)"""
    size, h = struct.unpack_from("!QI", p, 0)
    return size, h

