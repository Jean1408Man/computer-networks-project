# protocol.py — stub (definir MAGIC, VERSION, tipos de mensaje, headers, CRC, etc.)
from __future__ import annotations
import struct, zlib

MAGIC = b"L2MG"
VERSION = 1

# Tipos de mensaje mínimos para descubrimiento
HELLO     = 0x01
HELLO_ACK = 0x02

# Cabecera de nuestro protocolo (sobre el payload de Ethernet)
# MAGIC(4) | VER(1) | TYPE(1) | SEQ(4) | LEN(2) | FLAGS(1) | CRC32(4)
_HDR = struct.Struct("!4s B B I H B I")
HDR_LEN = _HDR.size  # 17 bytes

def pack_frame(msg_type: int, seq: int, payload: bytes, flags: int = 0) -> bytes:
    # CRC sobre el payload únicamente (simple para el arranque)
    crc = zlib.crc32(payload) & 0xffffffff
    return _HDR.pack(MAGIC, VERSION, msg_type, seq, len(payload), flags, crc) + payload

def unpack_frame(data: bytes):
    if len(data) < HDR_LEN:
        raise ValueError("frame demasiado corto")
    magic, ver, mtype, seq, plen, flags, crc = _HDR.unpack_from(data, 0)
    if magic != MAGIC or ver != VERSION:
        raise ValueError("MAGIC/VER inválidos")
    payload = data[HDR_LEN:HDR_LEN+plen]
    if len(payload) != plen:
        raise ValueError("LEN no coincide con datos")
    if (zlib.crc32(payload) & 0xffffffff) != crc:
        raise ValueError("CRC inválido")
    return mtype, seq, flags, payload
