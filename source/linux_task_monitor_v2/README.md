# Linux Task Monitor V2

L'agent collecte toutes les 15 s l'état du système, des processus (regroupés par programme) et des services systemd dans une base SQLite. L'API expose ces données et leur historique.

## Installation

```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Agent : `python -m agent.main`
API : `python -m uvicorn api.main:app --host 127.0.0.1 --port 8000`

L'API expose les lignes de commande des processus : ne l'écoutez pas sur `0.0.0.0` sans protection.

## Configuration (variables d'environnement)

| Variable | Défaut | Rôle |
|---|---|---|
| `LTM_DB_PATH` | `./monitor.db` | Chemin de la base SQLite (agent et API) |
| `LTM_INTERVAL_SECONDS` | `15` | Intervalle de collecte |
| `LTM_INCLUDE_KERNEL_THREADS` | `0` | Inclure les threads noyau |
| `LTM_TASK_SAMPLES_RETENTION_HOURS` | `48` | Rétention de l'historique par tâche |
| `LTM_SAMPLES_RETENTION_DAYS` | `30` | Rétention des mesures système |
| `LTM_RETENTION_CHECK_SECONDS` | `3600` | Fréquence du nettoyage |
| `LTM_ANALYSIS_INTERVAL_SECONDS` | `60` | Fréquence d'exécution des détecteurs |
| `LTM_THRESHOLD_<NOM>` | voir `agent/config.py` | Seuil d'un détecteur, ex. `LTM_THRESHOLD_TASK_CPU_PERCENT=90` |

## Détection des problèmes

Toutes les `LTM_ANALYSIS_INTERVAL_SECONDS`, l'agent analyse l'historique (pas seulement la dernière mesure) et ouvre des *findings* dans la table `findings`. Un finding reste ouvert tant que le problème est détecté (seuil de fermeture plus bas que le seuil d'ouverture) et passe à `resolved` après `LTM_THRESHOLD_RESOLVE_AFTER_RUNS` analyses (2 par défaut) sans détection. Une tâche concernée prend la sévérité de son pire finding ouvert dans `tasks.status`.

| Détecteur | Déclenchement par défaut |
|---|---|
| `sustained_task_cpu` | tâche ≥ 80 % CPU en moyenne sur 5 min (80 % des mesures au-dessus) ; critique si ≥ 75 % de la machine |
| `cpu_saturation` | CPU machine ≥ 90 % sur 5 min, charge 5 min ≥ 1,5 × cœurs ou PSI CPU ≥ 20 % |
| `memory_leak` | RSS en hausse régulière sur ≥ 1 h (R² ≥ 0,8, +20 % et +50 Mo), à nombre de processus constant ; critique si mémoire épuisée en < 24 h |
| `memory_pressure` | mémoire ≥ 90 % sur 5 min, swap ≥ 50 % et en hausse ou PSI mémoire ≥ 10 % |
| `oom_kill` | le noyau a tué un processus (OOM) dans les 15 dernières minutes |
| `zombies` | zombies non récupérés par le même parent depuis ≥ 2 min (ou ≥ 10 zombies) |
| `io_wait` | processus en état D sur 3 mesures consécutives, iowait ≥ 20 % sur 5 min ou PSI I/O ≥ 20 % |
| `disk_space` | point de montage ≥ 85 % ou inodes ≥ 90 % ; critique si ≥ 95 % ou plein dans < 24 h au rythme actuel |
| `service_failed` | service systemd en état `failed` |
| `restart_loop` | ≥ 3 redémarrages d'un service en 15 min |
| `fd_exhaustion` | processus à ≥ 80 % de sa limite de descripteurs de fichiers |
| `process_explosion` | nombre de processus d'une tâche × 5 en 10 min (et ≥ 50) |

## Modèle de données

- **Processus** : un programme = une tâche. Les processus d'un même exécutable dans la même unité systemd sont regroupés (CPU, mémoire, threads et descripteurs additionnés, `process_count`). Pour les interpréteurs (python, node, java…), le script ou module fait partie de l'identité. L'unité systemd du processus est dans `unit`.
- **Services systemd** : CPU et mémoire viennent de la comptabilité systemd (`CPUUsageNSec`, `MemoryCurrent`). Le nombre de redémarrages et le résultat sont dans `metadata`.
- `tasks.status` : `ok`, `warning`, `critical` ou `gone`. `tasks.state` : `active` ou `gone`. L'état brut (`sleeping`, `failed/failed`…) est dans `task_samples.raw_status`.
- Les services inactifs ne reçoivent une ligne d'historique que lorsque leur état ou leur nombre de redémarrages change ; les services en cours d'exécution sont mesurés à chaque cycle.
- `disk_samples` : utilisation de chaque point de montage local (octets et inodes) à chaque cycle.
- La base existante est migrée automatiquement au démarrage.

## Endpoints

`/system/latest`, `/tasks`, `/tasks/{task_id}`, `/tasks/{task_id}/history`, `/tasks/{task_id}/analysis`, `/analysis`, `/findings`, `/findings/{id}`

- `/analysis` : findings ouverts, les plus graves en premier.
- `/findings?status=open|resolved&severity=warning|critical&detector=memory_leak&task_id=...` (par défaut : ouverts).
- `/tasks/{task_id}/analysis` inclut les findings ouverts de la tâche.

Filtres : `/tasks?category=process|systemd`, `/tasks?status=ok|warning|critical|gone`, `/tasks?state=active|gone`, `/tasks?name=postgres`

Une tâche inconnue renvoie une erreur 404.

## Tests

```
pip install -r requirements-dev.txt
pytest
ruff check . && ruff format --check .
```
