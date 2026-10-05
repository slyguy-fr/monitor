import logging
import signal
import threading
import time

from .analyzer import analyze_latest
from .collector import Collector
from .config import load_settings
from .database import connect, init_db, prune, store_cycle

log = logging.getLogger("linux_task_monitor")


def run(settings, stop_event):
    conn = connect(settings.db_path)
    init_db(conn)
    collector = Collector(settings.include_kernel_threads)
    last_prune = 0.0
    log.info("Linux Task Monitor V2 démarré (base: %s).", settings.db_path)
    try:
        while not stop_event.is_set():
            started = time.monotonic()
            try:
                sample, tasks = collector.collect_all()
                store_cycle(conn, sample, tasks)
                for a in analyze_latest():
                    log.warning("[%s] %s", a["severity"].upper(), a["message"])
                log.info(
                    "%s | CPU %.1f%% | RAM %.1f%% | Tâches %d",
                    sample["timestamp"],
                    sample["cpu_percent"],
                    sample["memory_percent"],
                    len(tasks),
                )
                if started - last_prune >= settings.retention_check_seconds:
                    deleted = prune(
                        conn,
                        settings.task_samples_retention_hours,
                        settings.samples_retention_days,
                    )
                    last_prune = started
                    if any(deleted.values()):
                        log.info("Rétention: lignes supprimées %s", deleted)
            except Exception:
                log.exception("Erreur pendant le cycle de collecte")
            stop_event.wait(max(0.0, settings.interval_seconds - (time.monotonic() - started)))
    finally:
        conn.close()
        log.info("Arrêt.")


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    stop_event = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop_event.set())
    run(load_settings(), stop_event)


if __name__ == "__main__":
    main()
