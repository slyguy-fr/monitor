import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "monitor.db"


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    return int(value) if value not in (None, "") else default


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value in (None, ""):
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    db_path: Path
    interval_seconds: int
    include_kernel_threads: bool
    task_samples_retention_hours: int
    samples_retention_days: int
    retention_check_seconds: int


def load_settings() -> Settings:
    return Settings(
        db_path=Path(os.environ.get("LTM_DB_PATH") or DEFAULT_DB_PATH),
        interval_seconds=_env_int("LTM_INTERVAL_SECONDS", 15),
        include_kernel_threads=_env_bool("LTM_INCLUDE_KERNEL_THREADS", False),
        task_samples_retention_hours=_env_int("LTM_TASK_SAMPLES_RETENTION_HOURS", 48),
        samples_retention_days=_env_int("LTM_SAMPLES_RETENTION_DAYS", 30),
        retention_check_seconds=_env_int("LTM_RETENTION_CHECK_SECONDS", 3600),
    )
