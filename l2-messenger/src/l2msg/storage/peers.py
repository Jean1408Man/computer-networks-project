from time import time

class PeerTable:
    def __init__(self, ttl: int = 60):
        # ttl en segundos, por defecto 60 segundos
        self.ttl = ttl
        self.peers = {}

    def add_peer(self, mac: str, name: str):
        """Añade un nuevo peer o actualiza un peer existente"""
        self.peers[mac] = {'name': name, 'timestamp': time()}

    def remove_peer(self, mac: str):
        """Elimina un peer de la tabla"""
        if mac in self.peers:
            del self.peers[mac]

    def clean_up(self):
        """Limpia los peers que han superado el TTL"""
        current_time = time()
        for mac in list(self.peers.keys()):
            if current_time - self.peers[mac]['timestamp'] > self.ttl:
                del self.peers[mac]

    def get_peers(self):
        """Devuelve la lista de peers activos"""
        self.clean_up()  # Limpia antes de devolver
        return self.peers
