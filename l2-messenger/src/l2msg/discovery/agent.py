from __future__ import annotations
import time, struct, os, logging, threading, zlib
from l2msg.core import protocol
from l2msg.net.raw_socket import RawLink
from l2msg.utils.ifaces import mac_to_str
from l2msg.storage.peers import PeerTable
from l2msg.storage.messages import add as inbox_add  
from l2msg.crypto.secure import derive_pairwise_key, decrypt_payload, encrypt_payload
from l2msg.utils.config import load_config
from l2msg.transfer.transfer import flag_str, _mt
    

log = logging.getLogger("agent.listen")
_incoming = {}
_msg_incoming = {}
INBOX_DIR = os.getenv("L2MSG_INBOX", "/tmp/l2files")

MIN_PTXT_ACK = 16  # 16B de plaintext para ACK/ACCEPT/DONE vacíos

def _pack_sec(key, mtype, seq, payload, flags=0):
    # Si vamos a cifrar y el payload es muy chico (ACK/ACCEPT vacíos),
    # rellenamos a 16 bytes antes de cifrar para que (header+nonce+ct+tag) > 46B
    if key and len(payload) < MIN_PTXT_ACK and mtype in (
        protocol.FILE_ACCEPT, protocol.FILE_ACK, protocol.FILE_DONE,
        protocol.MSG_ACCEPT,  protocol.MSG_ACK,  protocol.MSG_DONE
    ):
        payload = payload + b"\x00" * (MIN_PTXT_ACK - len(payload))

    enc_payload, flags2 = encrypt_payload(key, mtype, seq, flags, payload)
    return protocol.pack_frame(mtype, seq, enc_payload, flags2)


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

def listen_forever(
    link: RawLink,
    node_name: str,
    peer_table: PeerTable,
    pause_event: 'threading.Event' = None,
    allow_msgs_event: 'threading.Event' = None,
    allow_files_event: 'threading.Event' = None,
):
    """
    Listener principal.
    - pause_event activo => NO llama a recv() (cede el socket al emisor local).
    - allow_msgs_event limpio => ignora/cancela MSG_*.
    - allow_files_event limpio => ignora/cancela FILE_*.
    Durante una recepción entrante, deshabilita temporalmente el otro tipo.
    """
    log.info("Escuchando en iface=%s etype=0x%04x mac=%s",
             link.iface, link.ether_type, mac_to_str(link.src_mac))
    os.makedirs(INBOX_DIR, exist_ok=True)

    cfg = load_config("configs/app.toml")

    while True:
        # Ceder el socket si alguien más lo está usando (envíos, discover, etc.)
        if pause_event is not None and pause_event.is_set():
            time.sleep(0.02)
            continue

        pkt = link.recv(timeout=0.1)
        if not pkt:
            continue

        src, _, p = pkt
        if src == link.src_mac:
            continue

        try:
            mtype, seq, flags, payload = protocol.unpack_frame(p)
            log.debug("RX %s %s seq=%d len=%d", flag_str(flags), _mt(mtype), seq, len(payload)) 
        except Exception as e:
            log.warning("Trama inválida en listen_forever: %s", e)
            continue

        mac = mac_to_str(src)

        # ------------------ CONTROL DE DISCOVERY ------------------
        if mtype == protocol.HELLO:
            name = parse_payload_name(payload)
            log.info("RX HELLO de %s name='%s'", mac, name)
            peer_table.add_peer(mac, name)
            send_ack(link, src, node_name, seq)

        elif mtype == protocol.HELLO_ACK:
            name = parse_payload_name(payload)
            log.info("RX HELLO_ACK de %s name='%s'", mac, name)
            peer_table.add_peer(mac, name)

        # ------------------ CONTROL DE ARCHIVOS -------------------
        elif mtype == protocol.FILE_OFFER:
            # Si archivos están deshabilitados, cancela inmediatamente
            if (allow_files_event is not None) and (not allow_files_event.is_set()):
                log.info("FILE_OFFER de %s recibido pero FILE RX está deshabilitado -> FILE_CANCEL", mac)
                link.send(src, protocol.pack_frame(protocol.FILE_CANCEL, seq, b""))
                continue

            # Deriva clave por par MAC (local, remoto)
            key = derive_pairwise_key(load_config("configs/app.toml"), link.src_mac, src)

            # Si viene cifrado, intentamos descifrar; si falla => CANCEL sin cifrar
            try:
                if flags & getattr(protocol, "FLAG_ENC", 0):
                    payload = decrypt_payload(key, mtype, seq, flags, payload)
            except Exception as e:
                log.warning("No se pudo descifrar FILE_OFFER de %s: %s -> FILE_CANCEL", mac, e)
                link.send(src, protocol.pack_frame(protocol.FILE_CANCEL, seq, b""))
                continue

            fname, fsize, crc_expected = protocol.parse_file_offer(payload)
            dst_path = f"{INBOX_DIR}/{fname}"
            log.info("RX FILE_OFFER de %s: %s (%d bytes, crc=0x%08x)", mac, fname, fsize, crc_expected)

            # 1) ACCEPT (cifrado si hay clave)
            try:
                link.send(src, _pack_sec(key, protocol.FILE_ACCEPT, seq, b""))
                log.info("TX FILE_ACCEPT a %s (seq=%d) para %s", mac, seq, fname)
            except Exception as e:
                log.exception("No se pudo enviar FILE_ACCEPT a %s: %s -> FILE_CANCEL", mac, e)
                try:
                    link.send(src, protocol.pack_frame(protocol.FILE_CANCEL, seq, b""))
                except Exception:
                    pass
                continue

            # 2) Preparar estado/archivo; si falla, cancelar enseguida
            try:
                os.makedirs(INBOX_DIR, exist_ok=True)
                fp = open(dst_path, "wb")
            except Exception as e:
                log.exception("No se pudo abrir destino %s: %s -> FILE_CANCEL", dst_path, e)
                try:
                    link.send(src, protocol.pack_frame(protocol.FILE_CANCEL, seq, b""))
                except Exception:
                    pass
                continue

            st = {
                "fp": fp,
                "name": fname,
                "size": fsize,
                "bytes": 0,
                "expected": 0,           # próximo seq esperado
                "crc": 0,                # crc32 acumulado
                "crc_expected": crc_expected,
                "_owns_files_lock": False,  # deshabilitamos MSG mientras recibimos FILE
                "key": key,              # NUEVO: guardamos clave de la sesión con ese peer
            }
            _incoming[mac] = st

            # Deshabilitar temporalmente MSG_* mientras dura el archivo
            if (allow_msgs_event is not None) and allow_msgs_event.is_set():
                allow_msgs_event.clear()
                st["_owns_files_lock"] = True
                log.debug("listen: MSG RX deshabilitado temporalmente (recibiendo FILE de %s)", mac)

            peer_table.add_peer(mac, peer_table.get_peers().get(mac, {}).get("name", ""))


        elif mtype == protocol.FILE_DATA:
            st = _incoming.get(mac)
            if not st:
                log.warning("RX FILE_DATA inesperado de %s seq=%d -> FILE_CANCEL", mac, seq)
                link.send(src, protocol.pack_frame(protocol.FILE_CANCEL, seq, b""))
                continue

            key = st.get("key")

            # Si viene cifrado, descifra; si falla => CANCEL sin cifrar
            try:
                if flags & getattr(protocol, "FLAG_ENC", 0):
                    payload = decrypt_payload(key, mtype, seq, flags, payload)
            except Exception as e:
                log.warning("No se pudo descifrar FILE_DATA de %s seq=%d: %s -> FILE_CANCEL", mac, seq, e)
                link.send(src, protocol.pack_frame(protocol.FILE_CANCEL, seq, b""))
                continue

            exp = st["expected"]
            if seq < exp:
                # Duplicado (probable reintento por ACK perdido)
                log.debug("Duplicado de %s seq=%d (expected=%d) -> re-ACK sin escribir", mac, seq, exp)
                link.send(src, _pack_sec(key, protocol.FILE_ACK, seq, b""))
                continue
            elif seq > exp:
                # Fuera de orden en stop-and-wait: NO ACK del futuro; re-ACK del último bueno
                last_ok = exp - 1
                if last_ok >= 0:
                    log.warning("Fuera de orden de %s seq=%d (expected=%d) -> re-ACK last_ok=%d",
                                mac, seq, exp, last_ok)
                    link.send(src, _pack_sec(key, protocol.FILE_ACK, last_ok, b""))
                else:
                    log.warning("Fuera de orden de %s seq=%d (expected=%d) -> sin ACK (last_ok<0)",
                                mac, seq, exp)
                continue

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

            link.send(src, _pack_sec(key, protocol.FILE_ACK, seq, b""))
            log.debug("ACK seq=%d enviado a %s", seq, mac)

        elif mtype == protocol.FILE_DONE:
            st = _incoming.pop(mac, None)
            key = st.get("key") if st else None

            if st:
                # Descifra payload si venía cifrado; si falla, reporta y no valida CRC
                try:
                    if flags & getattr(protocol, "FLAG_ENC", 0):
                        payload = decrypt_payload(key, mtype, seq, flags, payload)
                except Exception as e:
                    log.warning("No se pudo descifrar FILE_DONE de %s: %s", mac, e)

                st["fp"].close()
                rx_crc = None
                if len(payload) == 4:
                    (rx_crc,) = struct.unpack("!I", payload)
                expected_crc = rx_crc if rx_crc is not None else st["crc_expected"]
                ok = (st["bytes"] == st["size"]) and ((st["crc"] & 0xffffffff) == (expected_crc & 0xffffffff))
                log.info(
                    "RX FILE_DONE de %s -> archivo %s cerrado (%d/%d bytes, crc=0x%08x esperado=0x%08x) %s",
                    mac, st["name"], st["bytes"], st["size"],
                    st["crc"] & 0xffffffff, expected_crc & 0xffffffff,
                    "OK" if ok else "MISMATCH"
                )

                # Restaurar MSG_* si lo deshabilitamos nosotros
                if st.get("_owns_files_lock") and (allow_msgs_event is not None) and (not allow_msgs_event.is_set()):
                    allow_msgs_event.set()
                    log.debug("listen: MSG RX restaurado tras FILE_DONE de %s", mac)

        elif mtype == protocol.FILE_CANCEL:
            st = _incoming.pop(mac, None)
            if st:
                try:
                    st["fp"].close()
                except Exception:
                    pass
                log.warning("RX FILE_CANCEL de %s -> archivo %s cancelado (%d bytes)",
                            mac, st["name"], st["bytes"])
                if st.get("_owns_files_lock") and (allow_msgs_event is not None) and (not allow_msgs_event.is_set()):
                    allow_msgs_event.set()
                    log.debug("listen: MSG RX restaurado tras FILE_CANCEL de %s", mac)

        # ------------------ CONTROL DE MENSAJES -------------------
        elif mtype == protocol.MSG_OFFER:
            # Si mensajes están deshabilitados, cancela inmediatamente
            if (allow_msgs_event is not None) and (not allow_msgs_event.is_set()):
                log.info("MSG_OFFER de %s recibido pero MSG RX está deshabilitado -> MSG_CANCEL", mac)
                link.send(src, protocol.pack_frame(protocol.MSG_CANCEL, seq, b""))
                continue

            key = derive_pairwise_key(load_config("configs/app.toml"), link.src_mac, src)

            try:
                if flags & getattr(protocol, "FLAG_ENC", 0):
                    payload = decrypt_payload(key, mtype, seq, flags, payload)
                msize, crc_expected = protocol.parse_msg_offer(payload)
            except Exception as e:
                log.warning("No se pudo procesar MSG_OFFER de %s: %s -> MSG_CANCEL", mac, e)
                link.send(src, protocol.pack_frame(protocol.MSG_CANCEL, seq, b""))
                continue

            log.info("RX MSG_OFFER de %s: %d bytes (crc=0x%08x)", mac, msize, crc_expected)

            # 1) ACCEPT (cifrado si hay clave)
            try:
                link.send(src, _pack_sec(key, protocol.MSG_ACCEPT, seq, b""))
                log.info("TX MSG_ACCEPT a %s (seq=%d) tamaño=%d", mac, seq, msize)
            except Exception as e:
                log.exception("No se pudo enviar MSG_ACCEPT a %s: %s -> MSG_CANCEL", mac, e)
                try:
                    link.send(src, protocol.pack_frame(protocol.MSG_CANCEL, seq, b""))
                except Exception:
                    pass
                continue

            # 2) Preparar estado del mensaje
            _msg_incoming[mac] = {
                "buf": bytearray(),
                "size": msize,
                "expected": 0,
                "crc": 0,
                "crc_expected": crc_expected,
                "_owns_msgs_lock": False,   # deshabilitamos FILE mientras recibimos MSG
                "key": key,                 # NUEVO: guardamos clave de la sesión
            }
            log.debug("Estado inicial mensaje [%s]: size=%d expected=%d crc=0x%08x",
                    mac, _msg_incoming[mac]["size"], _msg_incoming[mac]["expected"],
                    _msg_incoming[mac]["crc"])

            # Deshabilitar temporalmente FILE_* mientras dura el mensaje
            if (allow_files_event is not None) and allow_files_event.is_set():
                allow_files_event.clear()
                _msg_incoming[mac]["_owns_msgs_lock"] = True
                log.debug("listen: FILE RX deshabilitado temporalmente (recibiendo MSG de %s)", mac)

            peer_table.add_peer(mac, peer_table.get_peers().get(mac, {}).get("name", ""))

        elif mtype == protocol.MSG_DATA:
            st = _msg_incoming.get(mac)
            if not st:
                log.warning("RX MSG_DATA inesperado de %s seq=%d -> MSG_CANCEL", mac, seq)
                link.send(src, protocol.pack_frame(protocol.MSG_CANCEL, seq, b""))
                log.debug("Enviado MSG_CANCEL a %s (no había estado de mensaje)", mac)
                continue

            key = st.get("key")

            try:
                if flags & getattr(protocol, "FLAG_ENC", 0):
                    payload = decrypt_payload(key, mtype, seq, flags, payload)
            except Exception as e:
                log.warning("No se pudo descifrar MSG_DATA de %s seq=%d: %s -> MSG_CANCEL", mac, seq, e)
                link.send(src, protocol.pack_frame(protocol.MSG_CANCEL, seq, b""))
                continue

            exp = st["expected"]
            if seq < exp:
                log.debug("RX MSG_DATA duplicado de %s (seq=%d < expected=%d) -> ACK eco", mac, seq, exp)
                link.send(src, _pack_sec(key, protocol.MSG_ACK, seq, b""))
                log.debug("Enviado MSG_ACK a %s (seq=%d, duplicado)", mac, seq)
                continue
            elif seq > exp:
                # Igual que en archivos: no ACK del futuro; re-ACK del último bueno
                last_ok = exp - 1
                if last_ok >= 0:
                    log.debug("RX MSG_DATA fuera de orden de %s (seq=%d > expected=%d) -> re-ACK last_ok=%d",
                            mac, seq, exp, last_ok)
                    link.send(src, _pack_sec(key, protocol.MSG_ACK, last_ok, b""))
                else:
                    log.debug("RX MSG_DATA fuera de orden de %s (seq=%d > expected=%d) -> sin ACK (last_ok<0)",
                            mac, seq, exp)
                continue

            remaining = st["size"] - len(st["buf"])
            if remaining < 0:
                log.warning("RX MSG_DATA de %s con remaining negativo (remaining=%d) — ignorando exceso", mac, remaining)

            take = payload if len(payload) <= remaining else payload[:max(0, remaining)]
            if len(payload) > remaining and remaining > 0:
                log.warning("Truncando payload de %s en seq=%d (payload=%d, remaining=%d)",
                            mac, seq, len(payload), remaining)

            if take:
                st["buf"].extend(take)
                st["crc"] = zlib.crc32(take, st["crc"])
                log.debug("Acumulado %d/%d bytes de %s (seq=%d, crc=0x%08x)",
                        len(st["buf"]), st["size"], mac, seq, st["crc"] & 0xffffffff)

            st["expected"] += 1
            link.send(src, _pack_sec(key, protocol.MSG_ACK, seq, b""))
            log.debug("Enviado MSG_ACK a %s (seq=%d)", mac, seq)

            if seq == 0:
                log.info("RX primer MSG_DATA de %s (%d/%d bytes)", mac, len(st["buf"]), st["size"])
            else:
                log.debug("RX MSG_DATA de %s seq=%d (%d/%d bytes)", mac, seq, len(st["buf"]), st["size"])

        elif mtype == protocol.MSG_DONE:
            st = _msg_incoming.pop(mac, None)
            key = st.get("key") if st else None
            if st:
                try:
                    if flags & getattr(protocol, "FLAG_ENC", 0):
                        payload = decrypt_payload(key, mtype, seq, flags, payload)
                except Exception as e:
                    log.warning("No se pudo descifrar MSG_DONE de %s: %s", mac, e)

                rx_crc = None
                if len(payload) == 4:
                    (rx_crc,) = struct.unpack("!I", payload)
                    log.debug("RX MSG_DONE de %s con crc en payload=0x%08x", mac, rx_crc)
                expected_crc = rx_crc if rx_crc is not None else st["crc_expected"]

                len_ok = (len(st["buf"]) == st["size"])
                crc_ok = ((st["crc"] & 0xffffffff) == (expected_crc & 0xffffffff))
                ok = len_ok and crc_ok

                text = st["buf"].decode("utf-8", errors="replace")

                # Persistimos en un archivo simple de inbox (opcional)
                os.makedirs(INBOX_DIR, exist_ok=True)
                msg_path = os.path.join(INBOX_DIR, "messages.log")
                with open(msg_path, "a", encoding="utf-8") as fp:
                    fp.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {mac}: {text}\n")

                # Guardar en memoria para el comando "inbox"
                try:
                    inbox_add(mac, text)
                except Exception as e:
                    log.exception("inbox_add falló: %s", e)

                log.info("RX MSG_DONE de %s -> mensaje (%d/%d bytes, crc_calc=0x%08x esperado=0x%08x) %s "
                        "[len_ok=%s crc_ok=%s]",
                        mac, len(st["buf"]), st["size"],
                        st["crc"] & 0xffffffff, expected_crc & 0xffffffff,
                        "OK" if ok else "MISMATCH",
                        "OK" if len_ok else "FAIL", "OK" if crc_ok else "FAIL")

                # Restaurar FILE_* si lo deshabilitamos nosotros
                if st.get("_owns_msgs_lock") and (allow_files_event is not None) and (not allow_files_event.is_set()):
                    allow_files_event.set()
                    log.debug("listen: FILE RX restaurado tras MSG_DONE de %s", mac)
        else:
            # (sin cambios) MSG_CANCEL
            if mtype == protocol.MSG_CANCEL:
                st = _msg_incoming.pop(mac, None)
                if st:
                    log.warning("RX MSG_CANCEL de %s -> mensaje descartado (%d bytes, expected=%d)",
                                mac, len(st["buf"]), st["expected"])
                    if st.get("_owns_msgs_lock") and (allow_files_event is not None) and (not allow_files_event.is_set()):
                        allow_files_event.set()
                        log.debug("listen: FILE RX restaurado tras MSG_CANCEL de %s", mac)
                else:
                    log.warning("RX MSG_CANCEL de %s sin estado previo; ignorado", mac)
