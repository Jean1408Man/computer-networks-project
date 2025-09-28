import os, time, logging, struct, zlib
from l2msg.core import protocol
from l2msg.net.raw_socket import RawLink
from l2msg.utils.config import load_config
from l2msg.utils.ifaces import mac_to_str  # para logs

RETRY_MAX = 10
ACK_TIMEOUT = 0.8  # s

log = logging.getLogger("transfer.send")

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
    max_payload = mtu_safe - 14 - protocol.HDR_LEN  # ≈ mtu_safe - 31
    size = os.path.getsize(path)
    name = os.path.basename(path)

    # CRC32 del archivo completo (integridad end-to-end)
    crc32_val = _crc32_file(path)

    log.info("Preparando envío de archivo: %s (%d bytes, crc=0x%08x) a %s",
             name, size, crc32_val, mac_to_str(dst_mac))
    log.debug("mtu_safe=%d, max_payload=%d", mtu_safe, max_payload)

    # 1) OFFER / ACCEPT
    offer = protocol.build_file_offer(name, size, crc32_val)
    seq = 0
    frame = protocol.pack_frame(protocol.FILE_OFFER, seq, offer)
    log.debug("Enviando FILE_OFFER seq=%d -> %s", seq, mac_to_str(dst_mac))
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
            log.debug("Ignorando trama de %s (esperando ACCEPT de %s)",
                      mac_to_str(src), mac_to_str(dst_mac))
            continue
        try:
            mtype, rseq, flags, payload = protocol.unpack_frame(p)
        except Exception as e:
            log.warning("Error desempaquetando trama durante OFFER: %s", e)
            continue
        log.debug("Recibido %s seq=%d de %s", _mt(mtype), rseq, mac_to_str(src))
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

    # 2) DATA + ACK (stop-and-wait)
    with open(path, "rb") as f:
        chunk_id = 0
        total_sent = 0
        while True:
            data = f.read(max_payload)  # usa todo el espacio útil
            if not data:
                break
            frame = protocol.pack_frame(protocol.FILE_DATA, chunk_id, data)
            attempts = 0
            while attempts < RETRY_MAX:
                log.debug("Enviando FILE_DATA seq=%d len=%d (intento %d)",
                          chunk_id, len(data), attempts + 1)
                link.send(dst_mac, frame)
                # esperar ACK(chunk_id)
                t_ack = time.monotonic()
                got = False
                while time.monotonic() - t_ack < ACK_TIMEOUT:
                    pkt = link.recv(timeout=0.2)
                    if not pkt:
                        continue
                    src, _, p = pkt
                    if src != dst_mac:
                        log.debug("Ignorando trama de %s (esperando ACK seq=%d de %s)",
                                  mac_to_str(src), chunk_id, mac_to_str(dst_mac))
                        continue
                    try:
                        mtype, rseq, _, _ = protocol.unpack_frame(p)
                    except Exception as e:
                        log.warning("Error desempaquetando trama durante DATA: %s", e)
                        continue
                    log.debug("Recibido %s seq=%d de %s", _mt(mtype), rseq, mac_to_str(src))
                    if mtype == protocol.FILE_ACK and rseq == chunk_id:
                        got = True
                        break
                if got:
                    total_sent += len(data)
                    log.debug("ACK seq=%d confirmado", chunk_id)
                    break
                attempts += 1
            if attempts == RETRY_MAX:
                log.error("Fallo permanente esperando ACK seq=%d -> CANCEL", chunk_id)
                link.send(dst_mac, protocol.pack_frame(protocol.FILE_CANCEL, chunk_id, b""))
                return False
            chunk_id += 1

    # 3) DONE (incluye CRC32 en el payload para verificación rápida)
    done_payload = struct.pack("!I", crc32_val)
    link.send(dst_mac, protocol.pack_frame(protocol.FILE_DONE, chunk_id, done_payload))
    log.info("Envío completo, total=%d bytes en %d chunks -> %s",
             total_sent, chunk_id, mac_to_str(dst_mac))
    return True


def _mt(mtype: int) -> str:
    names = {
        protocol.FILE_OFFER: "FILE_OFFER",
        protocol.FILE_ACCEPT: "FILE_ACCEPT",
        protocol.FILE_DATA: "FILE_DATA",
        protocol.FILE_ACK: "FILE_ACK",
        protocol.FILE_DONE: "FILE_DONE",
        protocol.FILE_CANCEL: "FILE_CANCEL",
    }
    return names.get(mtype, f"MTYPE_{mtype}")
