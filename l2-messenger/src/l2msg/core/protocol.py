# protocol.py — stub (definir MAGIC, VERSION, tipos de mensaje, headers, CRC, etc.)
from __future__ import annotations
import struct, zlib

MAGIC = b"L2MG"
VERSION = 1

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
