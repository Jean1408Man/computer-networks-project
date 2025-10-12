import os, time, logging, struct, zlib
from l2msg.core import protocol
from l2msg.net.raw_socket import RawLink
from l2msg.utils.config import load_config
from l2msg.utils.ifaces import mac_to_str  # para logs
from l2msg.crypto.secure import (
    derive_pairwise_key, encrypt_payload, decrypt_payload,
    NONCE_LEN, TAG_LEN
)
from l2msg.crypto.secure import NONCE_LEN, TAG_LEN

RETRY_MAX = 10
ACK_TIMEOUT = 0.8  # s

log = logging.getLogger("transfer.send")

def flag_str(flags: int) -> str:
    try:
        return "ENC" if (flags & protocol.FLAG_ENC) else "PLAIN"
    except Exception:
        return f"flags=0x{flags:02x}"


def _pack_sec(key, mtype, seq, payload, flags=0):
    enc_payload, flags2 = encrypt_payload(key, mtype, seq, flags, payload)
    log.info("TX %s %s seq=%d len=%d", "ENC" if (flags2 & protocol.FLAG_ENC) else "PLAIN",
              _mt(mtype), seq, len(enc_payload))
    return protocol.pack_frame(mtype, seq, enc_payload, flags2)

def _crc32_file(path: str) -> int:
    crc = 0
    # lee en chunks para no cargar todo a memoria
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            crc = zlib.crc32(chunk, crc)
    return crc & 0xffffffff

def send_file(link: RawLink, dst_mac: bytes, path: str) -> bool:
    cfg = load_config("configs/app.toml")
    mtu_safe = int(cfg["mtu_safe"])
    size = os.path.getsize(path)
    name = os.path.basename(path)

    key = derive_pairwise_key(cfg, link.src_mac, dst_mac)
    overhead = (NONCE_LEN + TAG_LEN) if key else 0
    max_payload = mtu_safe - 14 - protocol.HDR_LEN - overhead
    if max_payload <= 0:
        max_payload = 256  # fallback defensivo para no romper lecturas

    log.info(
        "MTU_SAFE=%d HDR_LEN=%d overhead=%d max_payload=%d",
        mtu_safe, protocol.HDR_LEN, overhead, max_payload
    )

    crc32_val = _crc32_file(path)
    log.info("Preparando envío de archivo: %s (%d bytes, crc=0x%08x) a %s",
             name, size, crc32_val, mac_to_str(dst_mac))

    # 1) OFFER / ACCEPT
    offer = protocol.build_file_offer(name, size, crc32_val)
    seq = 0
    frame = protocol.pack_frame(protocol.FILE_OFFER, seq, offer)
    log.info("Enviando FILE_OFFER seq=%d -> %s", seq, mac_to_str(dst_mac))
    link.send(dst_mac, frame)

    # Esperar ACCEPT (hasta 5s)
    t0 = time.monotonic()
    accepted = False
    while time.monotonic() - t0 < 5.0:
        pkt = link.recv(timeout=0.2)
        if not pkt:
            continue
        src, _, p = pkt
        if src != dst_mac:
            log.info("Ignorando trama de %s (esperando ACCEPT de %s)",
                      mac_to_str(src), mac_to_str(dst_mac))
            continue
        try:
            mtype, rseq, flags, payload = protocol.unpack_frame(p)
            # Autenticar respuesta si va cifrada (payload puede ser vacío)
            if flags & protocol.FLAG_ENC:
                _ = decrypt_payload(key, mtype, rseq, flags, payload)
        except Exception as e:
            log.warning("Error desempaquetando trama durante OFFER: %s", e)
            continue
        log.info("Recibido %s seq=%d de %s", _mt(mtype), rseq, mac_to_str(src))
        if mtype == protocol.FILE_ACCEPT:
            log.info("Peer %s aceptó el archivo", mac_to_str(dst_mac))
            accepted = True
            break
        if mtype == protocol.FILE_CANCEL:
            log.warning("Peer %s canceló durante OFFER", mac_to_str(dst_mac))
            return False

    if not accepted:
        log.error("Timeout esperando FILE_ACCEPT de %s", mac_to_str(dst_mac))
        return False

    with open(path, "rb") as f:
        chunk_id = 0
        total_sent = 0

        while True:
            data = f.read(max_payload)
            if not data:
                break  # no queda más por enviar

            frame = _pack_sec(key, protocol.FILE_DATA, chunk_id, data)

            acked = False
            for attempt in range(RETRY_MAX):
                link.send(dst_mac, frame)
                deadline = time.monotonic() + ACK_TIMEOUT

                while time.monotonic() < deadline:
                    pkt = link.recv(timeout=0.2)
                    if not pkt:
                        continue

                    src, _, p = pkt
                    if src != dst_mac:
                        continue  # de otro peer

                    try:
                        mtype, rseq, flags_rx, payload_rx = protocol.unpack_frame(p)
                    except Exception as e:
                        # basura/padding u otro tipo -> ignorar y seguir esperando
                        log.info("RX inválido durante DATA: %s | len=%d | head=%s",
                                (str(e) or e.__class__.__name__), len(p), p[:8].hex(" "))
                        continue

                    # ¿Es el ACK del chunk esperado?
                    if mtype == protocol.FILE_ACK and rseq == chunk_id:
                        if flags_rx & getattr(protocol, "FLAG_ENC", 0):
                            try:
                                _ = decrypt_payload(key, mtype, rseq, flags_rx, payload_rx)
                                log.info("Decrypt OK ACK seq=%d", rseq)
                            except Exception as e:
                                log.info("Decrypt FAIL ACK seq=%d: %s", rseq, (str(e) or e.__class__.__name__))
                                continue  # no contamos este ACK
                        acked = True
                        break  # sal del while de espera

                if acked:
                    total_sent += len(data)
                    log.info("ACK seq=%d confirmado (attempt=%d)", chunk_id, attempt + 1)
                    break  # sal del for de reintentos, pasa al siguiente chunk
                else:
                    log.info("Timeout esperando ACK seq=%d (reintento %d/%d)",
                            chunk_id, attempt + 1, RETRY_MAX)

            else:
                # se agotaron los RETRY_MAX sin ACK
                log.error("Fallo permanente esperando ACK seq=%d -> CANCEL", chunk_id)
                link.send(dst_mac, protocol.pack_frame(protocol.FILE_CANCEL, chunk_id, b""))
                return False

            # Solo se llega aquí si 'acked' fue True
            chunk_id += 1

    # 3) DONE (igual que ya tienes)
    done_payload = struct.pack("!I", crc32_val)
    link.send(dst_mac, _pack_sec(key, protocol.FILE_DONE, chunk_id, done_payload))
    log.info("Envío completo, total=%d bytes en %d chunks -> %s",
            total_sent, chunk_id, mac_to_str(dst_mac))
    return True


def _crc32_bytes(b: bytes) -> int:
    return zlib.crc32(b) & 0xffffffff

def send_message(link: RawLink, dst_mac: bytes, text: str) -> bool:
    """
    Envía un mensaje de texto confiable usando stop-and-wait:
    MSG_OFFER/MSG_ACCEPT, MSG_DATA/MSG_ACK, MSG_DONE/MSG_CANCEL.
    """
    cfg = load_config("configs/app.toml")
    mtu_safe = int(cfg["mtu_safe"])
    key = derive_pairwise_key(cfg, link.src_mac, dst_mac)

    # Overhead AEAD (nonce + tag) cuando ciframos
    overhead = (NONCE_LEN + TAG_LEN) if key else 0
    # 14 = cabecera Ethernet, protocol.HDR_LEN = cabecera L2MG
    max_payload = mtu_safe - 14 - protocol.HDR_LEN - overhead
    if max_payload <= 0:
        max_payload = 256  # fallback defensivo

    data = text.encode("utf-8")
    size = len(data)
    crc32_val = _crc32_bytes(data)

    log.info("Preparando envío de mensaje: %d bytes (crc=0x%08x) a %s",
             size, crc32_val, mac_to_str(dst_mac))
    log.info("mtu_safe=%d, max_payload=%d", mtu_safe, max_payload)

    # 1) OFFER / ACCEPT (OFFER cifrado si hay clave)
    offer = protocol.build_msg_offer(size, crc32_val)
    seq_offer = 0
    frame = _pack_sec(key, protocol.MSG_OFFER, seq_offer, offer)
    log.info("Enviando %s MSG_OFFER seq=%d -> %s",
             "ENC" if key else "PLAIN", seq_offer, mac_to_str(dst_mac))
    link.send(dst_mac, frame)

    # Esperar ACCEPT (hasta 5s)
    t0 = time.monotonic()
    accepted = False
    while time.monotonic() - t0 < 5.0:
        pkt = link.recv(timeout=0.2)
        if not pkt:
            continue
        src, _, p = pkt
        if src != dst_mac:
            continue  # de otro peer, ignora

        try:
            mtype, rseq, flags_rx, payload_rx = protocol.unpack_frame(p)
        except Exception as e:
            log.info("RX inválido durante MSG_OFFER: %s | len=%d | head=%s",
                      (str(e) or e.__class__.__name__), len(p), p[:8].hex(" "))
            continue

        if flags_rx & getattr(protocol, "FLAG_ENC", 0):
            try:
                _ = decrypt_payload(key, mtype, rseq, flags_rx, payload_rx)
                log.info("Decrypt OK: %s seq=%d", _mt(mtype), rseq)
            except Exception as e:
                log.info("Decrypt FAIL: %s seq=%d (%s)", _mt(mtype), rseq, (str(e) or e.__class__.__name__))
                continue  # no aceptes si no valida el tag

        if mtype == protocol.MSG_ACCEPT and rseq == seq_offer:
            log.info("Recibido MSG_ACCEPT seq=%d de %s", rseq, mac_to_str(dst_mac))
            accepted = True
            break
        if mtype == protocol.MSG_CANCEL:
            log.info("Recibido MSG_CANCEL de %s durante espera de ACCEPT", mac_to_str(dst_mac))
            return False

    if not accepted:
        log.info("Timeout esperando MSG_ACCEPT de %s", mac_to_str(dst_mac))
        return False

    # 2) DATA + ACK (stop-and-wait)
    chunk_id = 0
    total_sent = 0
    off = 0
    while off < size:
        chunk = data[off:off + max_payload]
        # MSG_DATA cifrado si hay clave
        frame = _pack_sec(key, protocol.MSG_DATA, chunk_id, chunk)

        for attempt in range(RETRY_MAX):
            log.info("Enviando %s MSG_DATA seq=%d len=%d (intento %d)",
                     "ENC" if key else "PLAIN", chunk_id, len(chunk), attempt + 1)
            link.send(dst_mac, frame)

            deadline = time.monotonic() + ACK_TIMEOUT
            got = False
            while time.monotonic() < deadline:
                pkt = link.recv(timeout=0.2)
                if not pkt:
                    continue
                src, _, p = pkt
                if src != dst_mac:
                    continue

                try:
                    mtype, rseq, flags_rx, payload_rx = protocol.unpack_frame(p)
                except Exception as e:
                    log.info("RX inválido durante MSG_DATA: %s | len=%d | head=%s",
                              (str(e) or e.__class__.__name__), len(p), p[:8].hex(" "))
                    continue

                if mtype == protocol.MSG_ACK and rseq == chunk_id:
                    if flags_rx & getattr(protocol, "FLAG_ENC", 0):
                        try:
                            _ = decrypt_payload(key, mtype, rseq, flags_rx, payload_rx)
                            log.info("Decrypt OK MSG_ACK seq=%d", rseq)
                        except Exception as e:
                            log.info("Decrypt FAIL MSG_ACK seq=%d: %s", rseq, (str(e) or e.__class__.__name__))
                            continue
                    got = True
                    break

            if got:
                total_sent += len(chunk)
                off += len(chunk)
                log.info("ACK seq=%d confirmado", chunk_id)
                break
            else:
                log.info("Timeout esperando MSG_ACK seq=%d (reintento %d/%d)",
                          chunk_id, attempt + 1, RETRY_MAX)

        else:
            # agotados los reintentos
            link.send(dst_mac, _pack_sec(key, protocol.MSG_CANCEL, chunk_id, b""))
            return False

        chunk_id += 1

    # 3) DONE con CRC32 para validación rápida (cifrado si hay clave)
    done_payload = struct.pack("!I", crc32_val)
    link.send(dst_mac, _pack_sec(key, protocol.MSG_DONE, chunk_id, done_payload))
    log.info("Mensaje enviado, total=%d bytes en %d chunks -> %s",
             total_sent, chunk_id, mac_to_str(dst_mac))
    return True


def _mt(t: int) -> str:
    names = {
        # FILE
        protocol.FILE_OFFER:   "FILE_OFFER",
        protocol.FILE_ACCEPT:  "FILE_ACCEPT",
        protocol.FILE_DATA:    "FILE_DATA",
        protocol.FILE_ACK:     "FILE_ACK",
        protocol.FILE_DONE:    "FILE_DONE",
        protocol.FILE_CANCEL:  "FILE_CANCEL",
        # MSG
        protocol.MSG_OFFER:    "MSG_OFFER",
        protocol.MSG_ACCEPT:   "MSG_ACCEPT",
        protocol.MSG_DATA:     "MSG_DATA",
        protocol.MSG_ACK:      "MSG_ACK",
        protocol.MSG_DONE:     "MSG_DONE",
        protocol.MSG_CANCEL:   "MSG_CANCEL",
    }
    # Fallback: muestra el tipo en hex para depurar (ej. TYPE_1a)
    try:
        return names.get(t, f"TYPE_{t:02x}")
    except Exception:
        # por si t no es int
        return f"TYPE_{t}"
