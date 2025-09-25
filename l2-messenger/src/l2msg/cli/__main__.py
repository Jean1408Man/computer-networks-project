import curses
import threading
import time
from l2msg.net.raw_socket import RawLink
from l2msg.discovery.agent import discover, listen_forever
from l2msg.utils.config import load_config
from l2msg.utils.ifaces import normalize_iface
from l2msg.storage.peers import PeerTable


# Clase para gestionar la tabla de peers
class PeerManager:
    def __init__(self, ttl=60):
        self.peer_table = PeerTable(ttl=ttl)

    def discover_peers(self, link, node_name, window_s=1.5):
        peers = discover(link, node_name, window_s=window_s, peer_table=self.peer_table)
        return peers

    def show_peers(self):
        return self.peer_table.get_peers()


# Función para ejecutar el comando listen
def listen_forever_thread(link, node_name, peer_manager):
    while True:
        listen_forever(link, node_name, peer_manager.peer_table)
        time.sleep(1)  # Añadimos un pequeño retraso para no saturar el hilo


# Función principal que maneja la UI y los comandos
def main(stdscr):
    stdscr.clear()  # Limpiar la pantalla

    # Configuración inicial
    cfg = load_config("configs/app.toml")
    iface = normalize_iface(cfg["iface"])
    etype = int(cfg["ether_type"])
    node_name = cfg["node_name"]

    # Inicialización del RawLink y PeerManager
    link = RawLink(iface=iface, ether_type=etype)
    peer_manager = PeerManager(ttl=60)

    # Iniciar el hilo de escucha
    listen_thread = threading.Thread(target=listen_forever_thread, args=(link, node_name, peer_manager), daemon=True)
    listen_thread.start()

    while True:
        stdscr.addstr(0, 0, "Comandos:")
        stdscr.addstr(1, 0, "1. Descubrir Peers (discover)")
        stdscr.addstr(2, 0, "2. Mostrar Peers (peers)")
        stdscr.addstr(3, 0, "3. Salir (exit)")
        stdscr.addstr(5, 0, "Seleccione un comando (1-3):")
        stdscr.refresh()

        key = stdscr.getch()

        if key == ord('1'):  # Comando discover
            peers = peer_manager.discover_peers(link, node_name)
            stdscr.clear()
            if not peers:
                stdscr.addstr(6, 0, "No se encontraron peers en la ventana de tiempo.")
            else:
                stdscr.addstr(6, 0, "Peers encontrados:")
                row = 7
                for mac, name in peers.items():
                    stdscr.addstr(row, 0, f"{mac} -> {name}")
                    row += 1
            stdscr.refresh()
            stdscr.getch()  # Espera una tecla para continuar

        elif key == ord('2'):  # Comando peers
            peers = peer_manager.show_peers()
            stdscr.clear()
            if not peers:
                stdscr.addstr(6, 0, "No hay peers disponibles.")
            else:
                stdscr.addstr(6, 0, "Peers activos:")
                row = 7
                for mac, data in peers.items():
                    stdscr.addstr(row, 0, f"{mac} -> {data['name']}")
                    row += 1
            stdscr.refresh()
            stdscr.getch()  # Espera una tecla para continuar

        elif key == ord('3'):  # Salir
            break

        else:
            stdscr.addstr(4, 0, "Comando no reconocido. Intente nuevamente.")
            stdscr.refresh()
            time.sleep(1)  # Pausa antes de volver a mostrar el menú


if __name__ == "__main__":
    curses.wrapper(main)
