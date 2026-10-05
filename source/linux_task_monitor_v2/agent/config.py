import os
from dataclasses import dataclass, field, fields
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
class Thresholds:
    """Detector thresholds; each can be overridden with LTM_THRESHOLD_<NAME>."""

    resolve_after_runs: int = 2
    # sustained_task_cpu (percent of one core)
    task_cpu_window_seconds: int = 300
    task_cpu_percent: float = 80.0
    task_cpu_clear_percent: float = 70.0
    task_cpu_min_fraction: float = 0.8
    task_cpu_critical_capacity_percent: float = 75.0
    # cpu_saturation / memory_pressure / io_wait (system window)
    system_window_seconds: int = 300
    system_cpu_percent: float = 90.0
    system_cpu_clear_percent: float = 80.0
    system_cpu_critical_percent: float = 98.0
    load_per_core: float = 1.5
    psi_cpu_percent: float = 20.0
    # memory_leak
    leak_min_window_seconds: int = 3600
    leak_max_window_seconds: int = 21600
    leak_min_samples: int = 30
    leak_min_r2: float = 0.8
    leak_min_growth_percent: float = 20.0
    leak_min_growth_mb: float = 50.0
    leak_critical_hours: float = 24.0
    # memory_pressure
    memory_percent: float = 90.0
    memory_clear_percent: float = 85.0
    memory_critical_percent: float = 95.0
    swap_percent: float = 50.0
    psi_memory_percent: float = 10.0
    psi_memory_critical_percent: float = 30.0
    # oom_kill
    oom_window_seconds: int = 900
    # zombies
    zombie_min_seconds: int = 120
    zombie_count: int = 10
    # io_wait
    dstate_consecutive_samples: int = 3
    iowait_percent: float = 20.0
    psi_io_percent: float = 20.0
    # disk_space
    disk_percent: float = 85.0
    disk_clear_percent: float = 80.0
    disk_critical_percent: float = 95.0
    inode_percent: float = 90.0
    inode_critical_percent: float = 95.0
    disk_forecast_window_seconds: int = 21600
    disk_forecast_min_window_seconds: int = 3600
    disk_forecast_min_samples: int = 10
    disk_forecast_min_r2: float = 0.7
    disk_full_critical_hours: float = 24.0
    # restart_loop
    restart_window_seconds: int = 900
    restart_count: int = 3
    # fd_exhaustion (percent of the soft RLIMIT_NOFILE)
    fd_percent: float = 80.0
    fd_critical_percent: float = 95.0
    # process_explosion
    explosion_window_seconds: int = 600
    explosion_factor: float = 5.0
    explosion_min_processes: int = 50


def load_thresholds() -> Thresholds:
    overrides = {}
    for f in fields(Thresholds):
        value = os.environ.get(f"LTM_THRESHOLD_{f.name.upper()}")
        if value not in (None, ""):
            overrides[f.name] = type(f.default)(value)
    return Thresholds(**overrides)


@dataclass(frozen=True)
class LLMSettings:
    model: str | None = None
    api_key: str | None = None
    base_url: str = "https://api.openai.com/v1"
    timeout_seconds: int = 60
    min_interval_seconds: int = 600

    @property
    def enabled(self):
        return bool(self.model)


def load_llm_settings() -> LLMSettings:
    return LLMSettings(
        model=os.environ.get("LTM_LLM_MODEL") or None,
        api_key=os.environ.get("LTM_LLM_API_KEY") or None,
        base_url=os.environ.get("LTM_LLM_BASE_URL") or LLMSettings.base_url,
        timeout_seconds=_env_int("LTM_LLM_TIMEOUT_SECONDS", 60),
        min_interval_seconds=_env_int("LTM_LLM_MIN_INTERVAL_SECONDS", 600),
    )


@dataclass(frozen=True)
class Settings:
    db_path: Path
    interval_seconds: int
    analysis_interval_seconds: int
    include_kernel_threads: bool
    task_samples_retention_hours: int
    samples_retention_days: int
    retention_check_seconds: int
    thresholds: Thresholds = field(default_factory=Thresholds)
    llm: LLMSettings = field(default_factory=LLMSettings)


def load_settings() -> Settings:
    return Settings(
        db_path=Path(os.environ.get("LTM_DB_PATH") or DEFAULT_DB_PATH),
        interval_seconds=_env_int("LTM_INTERVAL_SECONDS", 15),
        analysis_interval_seconds=_env_int("LTM_ANALYSIS_INTERVAL_SECONDS", 60),
        include_kernel_threads=_env_bool("LTM_INCLUDE_KERNEL_THREADS", False),
        task_samples_retention_hours=_env_int("LTM_TASK_SAMPLES_RETENTION_HOURS", 48),
        samples_retention_days=_env_int("LTM_SAMPLES_RETENTION_DAYS", 30),
        retention_check_seconds=_env_int("LTM_RETENTION_CHECK_SECONDS", 3600),
        thresholds=load_thresholds(),
        llm=load_llm_settings(),
    )
