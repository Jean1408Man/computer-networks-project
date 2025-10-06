from __future__ import annotations
import os, base64, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from l2msg.core import protocol

NONCE_LEN = 12
TAG_LEN = 16

def _load_psk_bytes(cfg: dict) -> bytes:
    c = (cfg.get("crypto") or {})
    psk = os.environ.get("L2MSG_PSK") or c.get("psk") or ""
    if isinstance(psk, str) and psk.startswith("base64:"):
        return base64.b64decode(psk.split(":", 1)[1])
    return (psk or "").encode("utf-8")

def derive_pairwise_key(cfg: dict, mac_a: bytes, mac_b: bytes) -> bytes | None:
    c = (cfg.get("crypto") or {})
    if not c or not c.get("enabled"):
        return None
    psk = _load_psk_bytes(cfg)
    if not psk:
        return None
    # par determinista (ordenado) para que ambos lados deriven lo mismo
    pair = mac_a + mac_b if mac_a < mac_b else mac_b + mac_a
    salt = hashlib.sha256(b"L2MSG-AESGCM-v1" + pair).digest()
    n = int(c.get("scrypt_n", 2**14))
    r = int(c.get("scrypt_r", 8))
    p = int(c.get("scrypt_p", 1))
    return hashlib.scrypt(psk, salt=salt, n=n, r=r, p=p, dklen=32)

def _aad(msg_type: int, seq: int, flags: int) -> bytes:
    # AAD incluye cabecera lógica para detectar manipulación (excepto LEN/CRC)
    # MAGIC(4) | VER(1) | TYPE(1) | SEQ(4) | FLAGS(1 c/FLAG_ENC)
    return protocol.MAGIC + bytes([protocol.VERSION, msg_type]) + seq.to_bytes(4, "big") + bytes([flags])

def encrypt_payload(key: bytes | None, msg_type: int, seq: int, flags: int, plaintext: bytes) -> tuple[bytes, int]:
    if not key:
        return plaintext, flags
    aes = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    flags2 = flags | protocol.FLAG_ENC
    ct = aes.encrypt(nonce, plaintext, _aad(msg_type, seq, flags2))
    return nonce + ct, flags2

def decrypt_payload(key: bytes | None, msg_type: int, seq: int, flags: int, enc_payload: bytes) -> bytes:
    # Si la trama declara FLAG_ENC, necesitamos clave sí o sí
    if flags & protocol.FLAG_ENC:
        if not key:
            raise ValueError("Trama cifrada pero no hay clave activa.")
        if len(enc_payload) < NONCE_LEN + TAG_LEN:
            raise ValueError("Payload cifrado demasiado corto.")
        nonce, ct = enc_payload[:NONCE_LEN], enc_payload[NONCE_LEN:]
        aes = AESGCM(key)
        return aes.decrypt(nonce, ct, _aad(msg_type, seq, flags))
    # sin cifrar
    return enc_payload
