import curses
import threading
import time
import os
import logging
from l2msg.net.raw_socket import RawLink
from l2msg.discovery.agent import discover, listen_forever
from l2msg.utils.config import load_config
from l2msg.utils.ifaces import normalize_iface
from l2msg.storage.peers import PeerTable
from l2msg.transfer.transfer import send_file
from l2msg.utils.logsetup import setup_logging, get_logger
from l2msg.transfer.transfer import send_file, send_message
from l2msg.storage.messages import list_all as inbox_list, clear as inbox_clear


# Clase para gestionar la tabla de peers
class PeerManager:
    def __init__(self, ttl=60):
        self.peer_table = PeerTable(ttl=ttl)

    def discover_peers(self, link, node_name, window_s=1.5):
        peers = discover(link, node_name, window_s=window_s, peer_table=self.peer_table)
        return peers

    def show_peers(self):
        return self.peer_table.get_peers()


# Hilo de escucha: respeta sending_event para no competir con send_file
def listen_forever_thread(link, node_name, peer_manager, log, sending_event: threading.Event):
    log.info("Hilo de escucha iniciado")
    try:
        listen_forever(link, node_name, peer_manager.peer_table, pause_event=sending_event)
    except Exception as e:
        log.exception("Excepción en listen_forever: %s", e)


# Función principal que maneja la UI y los comandos
def main(stdscr):
    stdscr.clear()  # Limpiar la pantalla
    curses.curs_set(0)  # ocultar cursor en el menú

    # Configuración inicial
    cfg = load_config("configs/app.toml")

    # --- Inicialización de logging (a archivo, según tu logsetup) ---
    setup_logging(cfg)
    log = get_logger("ui")
    log.info("UI iniciada")

    iface = normalize_iface(cfg["iface"])
    etype = int(cfg["ether_type"])
    node_name = cfg["node_name"]
    log.info("Config: iface=%s ether_type=0x%04x node_name=%s", iface, etype, node_name)

    # Inicialización del RawLink y PeerManager
    try:
        link = RawLink(iface=iface, ether_type=etype)
        # Algunos RawLink no exponen src_mac_str; lo derivamos si no está
        src_mac_str = getattr(link, "src_mac_str", None)
        if not src_mac_str and hasattr(link, "src_mac"):
            src_mac_str = ":".join(f"{b:02x}" for b in link.src_mac)
        log.info("RawLink creado: src_mac=%s", src_mac_str or "desconocida")
    except Exception as e:
        log.exception("No se pudo crear RawLink: %s", e)
        stdscr.addstr(0, 0, "Error inicializando la interfaz. Revisa los logs.")
        stdscr.refresh()
        stdscr.getch()
        return

    peer_manager = PeerManager(ttl=60)
    log.info("PeerManager TTL=%d", 60)

    # Evento para pausar el listener durante transferencias
    sending_event = threading.Event()

    # Iniciar el hilo de escucha (pausable)
    listen_thread = threading.Thread(
        target=listen_forever_thread,
        args=(link, node_name, peer_manager, log, sending_event),
        daemon=True
    )
    listen_thread.start()

    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, "Comandos:")
        stdscr.addstr(1, 0, "1. Descubrir Peers (discover)")
        stdscr.addstr(2, 0, "2. Mostrar Peers (peers)")
        stdscr.addstr(3, 0, "3. Salir (exit)")
        stdscr.addstr(4, 0, "4. Enviar archivo (sendfile)")
        stdscr.addstr(5, 0, "5. Enviar mensaje (sendmsg)")
        stdscr.addstr(6, 0, "6. Ver mensajes recibidos (inbox)")
        stdscr.addstr(7, 0, "Seleccione un comando (1-6):")
        stdscr.refresh()

        key = stdscr.getch()

        if key == ord('1'):  # Comando discover
            log.info("Comando: discover")
            peers = peer_manager.discover_peers(link, node_name)
            stdscr.clear()
            if not peers:
                stdscr.addstr(6, 0, "No se encontraron peers en la ventana de tiempo.")
                log.info("Discover: 0 peers")
            else:
                stdscr.addstr(6, 0, "Peers encontrados:")
                row = 7
                for mac, name in peers.items():
                    stdscr.addstr(row, 0, f"{mac} -> {name}")
                    row += 1
                log.info("Discover: %d peers", len(peers))
            stdscr.refresh()
            stdscr.getch()

        elif key == ord('2'):  # Comando peers
            log.info("Comando: peers")
            peers = peer_manager.show_peers()
            stdscr.clear()
            if not peers:
                stdscr.addstr(6, 0, "No hay peers disponibles.")
                log.info("Peers activos: 0")
            else:
                stdscr.addstr(6, 0, "Peers activos:")
                row = 7
                for mac, data in peers.items():
                    stdscr.addstr(row, 0, f"{mac} -> {data['name']}")
                    row += 1
                log.info("Peers activos: %d", len(peers))
            stdscr.refresh()
            stdscr.getch()

        elif key == ord('3'):  # Salir
            log.info("Comando: exit")
            break

        elif key == ord('4'):  # Enviar archivo
            log.info("Comando: sendfile (solicitando datos)")
            stdscr.clear()
            stdscr.addstr(6, 0, "Ingrese la MAC destino (ej. aa:bb:cc:dd:ee:ff): ")
            curses.echo()
            mac_str = stdscr.getstr(7, 0, 32).decode().strip()

            stdscr.addstr(9, 0, "Ingrese la ruta del archivo a enviar: ")
            path = stdscr.getstr(10, 0, 256).decode().strip()
            curses.noecho()

            if not os.path.isfile(path):
                log.warning("Ruta inválida de archivo: %s", path)
                stdscr.addstr(12, 0, "Archivo no encontrado.")
                stdscr.refresh()
                stdscr.getch()
                continue

            try:
                dst_mac = bytes.fromhex(mac_str.replace(":", "").lower())
            except ValueError:
                log.error("MAC inválida: %s", mac_str)
                stdscr.addstr(12, 0, "MAC inválida. Use formato aa:bb:cc:dd:ee:ff")
                stdscr.refresh()
                stdscr.getch()
                continue

            # Pausar el listener para no competir por recv()
            log.debug("Pausando listener para enviar...")
            sending_event.set()
            try:
                log.info("Intentando enviar archivo '%s' a %s", path, mac_str)
                ok = send_file(link, dst_mac, path)
                log.info("Resultado envío: %s", "OK" if ok else "FAIL")
            except Exception as e:
                log.exception("Excepción durante send_file: %s", e)
                ok = False
            finally:
                sending_event.clear()
                log.debug("Listener reanudado")

            msg = "Archivo enviado correctamente." if ok else "Error al enviar archivo."
            stdscr.addstr(12, 0, msg)
            stdscr.refresh()
            stdscr.getch()

        elif key == ord('5'):  # Enviar mensaje
            log.info("Comando: sendmsg (solicitando datos)")
            stdscr.clear()
            stdscr.addstr(6, 0, "Ingrese la MAC destino (ej. aa:bb:cc:dd:ee:ff): ")
            curses.echo()
            mac_str = stdscr.getstr(7, 0, 32).decode().strip()

            stdscr.addstr(9, 0, "Ingrese el mensaje (una línea): ")
            text = stdscr.getstr(10, 0, 4000).decode().strip()
            curses.noecho()

            try:
                dst_mac = bytes.fromhex(mac_str.replace(":", "").lower())
            except ValueError:
                log.error("MAC inválida: %s", mac_str)
                stdscr.addstr(12, 0, "MAC inválida. Use formato aa:bb:cc:dd:ee:ff")
                stdscr.refresh()
                stdscr.getch()
                continue

            # Pausar listener para no competir por recv()
            log.debug("Pausando listener para enviar MSG...")
            sending_event.set()
            try:
                log.info("Intentando enviar mensaje a %s", mac_str)
                ok = send_message(link, dst_mac, text)
                log.info("Resultado envío MSG: %s", "OK" if ok else "FAIL")
            except Exception as e:
                log.exception("Excepción durante send_message: %s", e)
                ok = False
            finally:
                sending_event.clear()
                log.debug("Listener reanudado")

            msg = "Mensaje enviado correctamente." if ok else "Error al enviar mensaje."
            stdscr.addstr(12, 0, msg)
            stdscr.refresh()
            stdscr.getch()

        elif key == ord('6'):  # Ver mensajes recibidos
            log.info("Comando: inbox (listar mensajes)")
            stdscr.clear()
            stdscr.addstr(0, 0, "📨 Mensajes recibidos (más recientes al final):")
            msgs = inbox_list()
            if not msgs:
                stdscr.addstr(2, 0, "(no hay mensajes aún)")
                stdscr.addstr(4, 0, "Presione cualquier tecla para volver…")
                stdscr.refresh()
                stdscr.getch()
                continue

            # Pintar con paginado simple
            row = 2
            h, w = stdscr.getmaxyx()
            per_page = max(1, h - 6)
            i = 0
            while True:
                stdscr.clear()
                stdscr.addstr(0, 0, "📨 Mensajes recibidos (más recientes al final):")
                end = min(i + per_page, len(msgs))
                for idx in range(i, end):
                    m = msgs[idx]
                    ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(m["ts"]))
                    line = f"{idx+1:>3} | {ts} | {m['mac']} | {m['text']}"
                    stdscr.addnstr(row + (idx - i), 0, line, w - 1)
                stdscr.addstr(h-3, 0, "[↑/↓] navega  [C] limpiar inbox  [Q] volver")
                stdscr.refresh()

                ch = stdscr.getch()
                if ch in (ord('q'), ord('Q')):
                    break
                elif ch in (curses.KEY_DOWN, ord('j')):
                    if end < len(msgs):
                        i = min(len(msgs)-1, i + 1)
                elif ch in (curses.KEY_UP, ord('k')):
                    if i > 0:
                        i = max(0, i - 1)
                elif ch in (ord('c'), ord('C')):
                    log.warning("Comando: inbox -> limpiar")
                    inbox_clear()
                    msgs = []
                    stdscr.addstr(2, 0, "(inbox vaciado)")
                    stdscr.addstr(4, 0, "Presione cualquier tecla para volver…")
                    stdscr.refresh()
                    stdscr.getch()
                    break



        else:
            log.debug("Tecla no reconocida: %r", key)
            stdscr.addstr(4, 0, "Comando no reconocido. Intente nuevamente.")
            stdscr.refresh()
            time.sleep(1)


if __name__ == "__main__":
    curses.wrapper(main)
