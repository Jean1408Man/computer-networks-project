import logging
import os
from logging.handlers import RotatingFileHandler

_LEVELS = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}

def setup_logging(cfg):
    log_cfg = cfg.get("logging", {}) if isinstance(cfg, dict) else {}
    level = _LEVELS.get(str(log_cfg.get("level", "INFO")).upper(), logging.INFO)
    log_file = log_cfg.get("file", "logs/l2msg.log")
    max_bytes = int(log_cfg.get("max_bytes", 5 * 1024 * 1024))
    backup_count = int(log_cfg.get("backup_count", 3))
    console = bool(log_cfg.get("console", False))  # por defecto, apagado

    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    root = logging.getLogger()
    root.setLevel(level)

    # Limpia handlers previos
    for h in list(root.handlers):
        root.removeHandler(h)

    fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)s [%(threadName)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Archivo rotativo
    fh = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
    fh.setFormatter(fmt)
    fh.setLevel(level)
    root.addHandler(fh)

    # (Opcional) consola — desactivada por defecto para no chocar con curses
    if console:
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        sh.setLevel(level)
        root.addHandler(sh)

    # Evita que libs externas vuelvan a imprimir a consola
    logging.getLogger("asyncio").propagate = False

    root.info("Logging inicializado (level=%s, file=%s, console=%s)",
              logging.getLevelName(level), log_file, console)

def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
