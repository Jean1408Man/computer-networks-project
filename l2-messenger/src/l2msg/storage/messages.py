from collections import deque
from threading import RLock
import time

_MAX = 1000  

_inbox = deque(maxlen=_MAX)
_lock = RLock()

def add(mac: str, text: str, ts: float | None = None):
    """Agrega un mensaje al inbox en memoria."""
    if ts is None:
        ts = time.time()
    item = {"ts": ts, "mac": mac, "text": text}
    with _lock:
        _inbox.append(item)

def list_all():
    """Devuelve una copia de los mensajes (lista de dicts)."""
    with _lock:
        return list(_inbox)

def clear():
    """Limpia el inbox."""
    with _lock:
        _inbox.clear()
