import logging
import signal
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .collector import Collector
from .config import load_settings
from .context import attach_contexts
from .database import connect, init_db, prune, store_cycle
from .findings import run_analysis
from .summary import update_summary

log = logging.getLogger("linux_task_monitor")


def _analyze(conn, settings):
    opened, resolved = run_analysis(conn, settings.thresholds)
    for f in opened:
        log.warning("[%s] %s", f.severity.upper(), f.title)
    for row in resolved:
        log.info("[RÉSOLU] %s", row["title"])


def _background(db_path, llm):
    conn = connect(db_path)
    try:
        attach_contexts(conn)
        update_summary(conn, llm)
    except Exception:
        log.exception("Erreur pendant la collecte des diagnostics ou le résumé")
    finally:
        conn.close()


def run(settings, stop_event):
    conn = connect(settings.db_path)
    init_db(conn)
    collector = Collector(settings.include_kernel_threads)
    # Diagnostics (du, journalctl…) and the LLM call can be slow: keep them off the collection loop.
    context_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="context")
    context_job = None
    last_prune = last_analysis = float("-inf")
    log.info("Linux Task Monitor V2 démarré (base: %s).", settings.db_path)
    try:
        while not stop_event.is_set():
            started = time.monotonic()
            try:
                sample, tasks, disks = collector.collect_all()
                store_cycle(conn, sample, tasks, disks)
                log.info(
                    "%s | CPU %.1f%% | RAM %.1f%% | Tâches %d",
                    sample["timestamp"],
                    sample["cpu_percent"],
                    sample["memory_percent"],
                    len(tasks),
                )
                if started - last_analysis >= settings.analysis_interval_seconds:
                    last_analysis = started
                    _analyze(conn, settings)
                    if context_job is None or context_job.done():
                        context_job = context_pool.submit(
                            _background, settings.db_path, settings.llm
                        )
                if started - last_prune >= settings.retention_check_seconds:
                    last_prune = started
                    deleted = prune(
                        conn,
                        settings.task_samples_retention_hours,
                        settings.samples_retention_days,
                    )
                    if any(deleted.values()):
                        log.info("Rétention: lignes supprimées %s", deleted)
            except Exception:
                log.exception("Erreur pendant le cycle de collecte")
            stop_event.wait(max(0.0, settings.interval_seconds - (time.monotonic() - started)))
    finally:
        context_pool.shutdown(wait=False, cancel_futures=True)
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
